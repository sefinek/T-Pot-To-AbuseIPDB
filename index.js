//   Copyright 2025 © by Sefinek. All Rights Reserved.
//                https://sefinek.net

const banner = require('./scripts/banners/t-pot.js');
const { axiosService } = require('./scripts/services/axios.js');
const { saveBufferToFile, loadBufferFromFile, sendBulkReport, BULK_REPORT_BUFFER } = require('./scripts/services/bulk.js');
const { loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported } = require('./scripts/services/cache.js');
const { refreshServerIPs, getServerIPs } = require('./scripts/services/ipFetcher.js');
const { repoSlug, repoUrl } = require('./scripts/repo.js');
const isSpecialPurposeIP = require('./scripts/isSpecialPurposeIP.js');
const logger = require('./scripts/logger.js');
const config = require('./config.js');
const { ABUSEIPDB_API_KEY, SERVER_ID, EXTENDED_LOGS, AUTO_UPDATE_ENABLED, AUTO_UPDATE_SCHEDULE, DISCORD_WEBHOOK_ENABLED, DISCORD_WEBHOOK_URL } = config.MAIN;

const ABUSE_STATE = { isLimited: false, isBuffering: false, sentBulk: false };
const RATE_LIMIT_LOG_INTERVAL = 10 * 60 * 1000;
const BUFFER_STATS_INTERVAL = 5 * 60 * 1000;

const nextRateLimitReset = () => {
	const now = new Date();
	return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 1));
};

let LAST_RATELIMIT_LOG = 0, LAST_STATS_LOG = 0, RATELIMIT_RESET = nextRateLimitReset();

const checkRateLimit = async () => {
	const now = Date.now();
	if (now - LAST_STATS_LOG >= BUFFER_STATS_INTERVAL && BULK_REPORT_BUFFER.size > 0) LAST_STATS_LOG = now;

	if (ABUSE_STATE.isLimited) {
		if (now >= RATELIMIT_RESET.getTime()) {
			ABUSE_STATE.isLimited = false;
			ABUSE_STATE.isBuffering = false;
			if (!ABUSE_STATE.sentBulk && BULK_REPORT_BUFFER.size > 0) await sendBulkReport();
			RATELIMIT_RESET = nextRateLimitReset();
			ABUSE_STATE.sentBulk = false;
			logger.log(`Rate limit reset. Next reset scheduled at ${RATELIMIT_RESET.toISOString()}`, 1);
		} else if (now - LAST_RATELIMIT_LOG >= RATE_LIMIT_LOG_INTERVAL) {
			const minutesLeft = Math.ceil((RATELIMIT_RESET.getTime() - now) / 60000);
			logger.log(`Rate limit is still active. Collected ${BULK_REPORT_BUFFER.size} IPs. Waiting for reset in ${minutesLeft} minute(s) (${RATELIMIT_RESET.toISOString()})`, 1);
			LAST_RATELIMIT_LOG = now;
		}
	}
};

const reportIp = async (honeypot, { srcIp, dpt = 'N/A', proto = 'N/A', timestamp }, categories, comment) => {
	if (!srcIp) return logger.log(`${honeypot} -> Missing source IP (srcIp)`, 3, true);

	// Check IP
	const ips = getServerIPs();
	if (!Array.isArray(ips)) return logger.log(`${honeypot} -> For some reason, 'ips' from 'getServerIPs()' is not an array. Received: ${ips}`, 3, true);

	if (ips.includes(srcIp)) return logger.log(`${honeypot} -> Ignoring own IP address: PROTO=${proto?.toLowerCase()} SRC=${srcIp} DPT=${dpt}`, 0, EXTENDED_LOGS);
	if (isSpecialPurposeIP(srcIp)) return logger.log(`${honeypot} -> Ignoring local IP address: PROTO=${proto?.toLowerCase()} SRC=${srcIp} DPT=${dpt}`, 0, EXTENDED_LOGS);
	if (proto === 'UDP') {
		if (EXTENDED_LOGS) logger.log(`${honeypot} -> Skipping UDP traffic: SRC=${srcIp} DPT=${dpt}`);
		return;
	}

	// Report
	if (isIPReportedRecently(srcIp)) return;
	await checkRateLimit();

	if (ABUSE_STATE.isBuffering) {
		if (BULK_REPORT_BUFFER.has(srcIp)) return;
		BULK_REPORT_BUFFER.set(srcIp, { categories, timestamp, comment });
		await saveBufferToFile();
		return logger.log(`${honeypot} -> Queued ${srcIp} for bulk report (collected ${BULK_REPORT_BUFFER.size} IPs)`, 1);
	}

	try {
		const { data: res } = await axiosService.post('/report', {
			ip: srcIp,
			categories,
			comment,
		});

		markIPAsReported(srcIp);
		await saveReportedIPs();

		logger.log(`${honeypot} -> ✅ Reported ${srcIp} [${dpt}/${proto}] | Categories: ${categories} | Abuse: ${res.data.abuseConfidenceScore}%`, 1);
	} catch (err) {
		const status = err.response?.status ?? 'unknown';
		if (status === 429 && JSON.stringify(err.response?.data || {}).includes('Daily rate limit')) {
			if (!ABUSE_STATE.isLimited) {
				ABUSE_STATE.isLimited = true;
				ABUSE_STATE.isBuffering = true;
				ABUSE_STATE.sentBulk = false;
				LAST_RATELIMIT_LOG = Date.now();
				RATELIMIT_RESET = nextRateLimitReset();
				logger.log(`${honeypot} -> Daily AbuseIPDB limit reached. Buffering reports until ${RATELIMIT_RESET.toLocaleString()}`, 0, true);
			}

			if (!BULK_REPORT_BUFFER.has(srcIp)) {
				BULK_REPORT_BUFFER.set(srcIp, { timestamp, categories, comment });
				await saveBufferToFile();
				logger.log(`${honeypot} -> Queued ${srcIp} for bulk report due to rate limit`, 1);
			}
		} else {
			logger.log(`${honeypot} -> Failed to report ${srcIp} [${dpt}/${proto}]; ${err.response?.data?.errors ? JSON.stringify(err.response.data.errors) : err.message}`, status === 429 ? 0 : 3);
		}
	}
};

(async () => {
	banner();

	// Auto updates
	if (AUTO_UPDATE_ENABLED && AUTO_UPDATE_SCHEDULE && SERVER_ID !== 'development') {
		await require('./scripts/services/updates.js');
	} else {
		await require('./scripts/services/version.js');
	}

	// Fetch IPs
	await refreshServerIPs();

	// Load cache
	await loadReportedIPs();

	// Bulk
	await loadBufferFromFile();
	if (BULK_REPORT_BUFFER.size > 0 && !ABUSE_STATE.isLimited) {
		logger.log(`Found ${BULK_REPORT_BUFFER.size} IPs in buffer after restart. Sending bulk report...`);
		await sendBulkReport();
	}

	// Watch
	const watchers = [
		require('./scripts/honeypots/dionaea.js')(reportIp),
		require('./scripts/honeypots/honeytrap.js')(reportIp),
		require('./scripts/honeypots/cowrie.js')(reportIp),
	];

	['SIGINT', 'SIGTERM'].forEach(signal => {
		process.on(signal, async () => {
			logger.log(`Caught ${signal}! Graceful shutdown started...`, 0, true);
			try {
				for (const watcher of watchers) {
					if (typeof watcher?.flush === 'function') await watcher.flush();
					if (typeof watcher?.tail?.quit === 'function') await watcher.tail.quit();
				}
				logger.log('All watchers closed. Exiting...', 1, true);
			} catch (err) {
				logger.log(`Error during shutdown: ${err.message}`, 3, true);
			} finally {
				process.exit(0);
			}
		});
	});

	process.on('uncaughtException', err => {
		logger.log(`Uncaught exception: ${err.stack || err.message}`, 3, true);
	});

	process.on('unhandledRejection', reason => {
		logger.log(`Unhandled rejection: ${reason}`, 3, true);
	});

	// Summaries
	if (DISCORD_WEBHOOK_ENABLED && DISCORD_WEBHOOK_URL) await require('./scripts/services/summaries.js')();

	// Ready
	await logger.webhook(`[${repoSlug}](${repoUrl}) was successfully started!`, 0x59D267);
	process.send?.('ready');
})();

module.exports = reportIp;
//   Copyright 2024-2026 © by Sefinek. All Rights Reserved.
//                   https://sefinek.net

const banner = require('./scripts/banners/t-pot.js');
const { axiosService } = require('./scripts/services/axios.js');
const { saveBufferToFile, loadBufferFromFile, sendBulkReport, BULK_REPORT_BUFFER } = require('./scripts/services/bulk.js');
const { loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported } = require('./scripts/services/cache.js');
const ABUSE_STATE = require('./scripts/services/state.js');
const { refreshServerIPs, getServerIPs } = require('./scripts/services/ipFetcher.js');
const { repoSlug, repoUrl } = require('./scripts/repo.js');
const isSpecialPurposeIP = require('./scripts/isSpecialPurposeIP.js');
const logger = require('./scripts/logger.js');
const resolvePath = require('./scripts/pathResolver.js');
const config = require('./config.js');
const { SERVER_ID, EXTENDED_LOGS, AUTO_UPDATE_ENABLED, AUTO_UPDATE_SCHEDULE, DISCORD_WEBHOOK_ENABLED, DISCORD_WEBHOOK_URL, COWRIE_LOG_FILE, DIONAEA_LOG_FILE, HONEYTRAP_LOG_FILE, CACHE_FILE, LOG_IP_HISTORY_DIR } = config.MAIN;

const RATE_LIMIT_LOG_INTERVAL = 10 * 60 * 1000;
const BUFFER_STATS_INTERVAL = 5 * 60 * 1000;
const MAX_BUFFER_SIZE = 100000;

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
			logger.success(`Rate limit reset. Next reset scheduled at \`${RATELIMIT_RESET.toISOString()}\`.`, { discord: true });
		} else if (now - LAST_RATELIMIT_LOG >= RATE_LIMIT_LOG_INTERVAL) {
			const minutesLeft = Math.ceil((RATELIMIT_RESET.getTime() - now) / 60000);
			logger.info(`Rate limit is still active, collected ${BULK_REPORT_BUFFER.size} IPs. Waiting for reset in ${minutesLeft} minute(s) (${RATELIMIT_RESET.toISOString()})...`);
			LAST_RATELIMIT_LOG = now;
		}
	}
};

const reportIp = async (honeypot, { srcIp, dpt = 'N/A', proto = 'N/A', timestamp }, categories, comment) => {
	if (!srcIp) return logger.error(`${honeypot} -> Missing source IP (srcIp)`);

	// Check IP
	const ips = getServerIPs();
	if (!Array.isArray(ips)) return logger.error(`${honeypot} -> For some reason, 'ips' from 'getServerIPs()' is not an array. Received: ${ips}`);

	if (ips.includes(srcIp)) {
		if (EXTENDED_LOGS) logger.info(`${honeypot} -> Ignoring own IP address: PROTO=${proto?.toLowerCase()} SRC=${srcIp} DPT=${dpt}`);
		return;
	}

	if (isSpecialPurposeIP(srcIp)) {
		if (EXTENDED_LOGS) logger.info(`${honeypot} -> Ignoring local IP address: PROTO=${proto?.toLowerCase()} SRC=${srcIp} DPT=${dpt}`);
		return;
	}

	if (proto === 'UDP') {
		if (EXTENDED_LOGS) logger.info(`${honeypot} -> Skipping UDP traffic: SRC=${srcIp} DPT=${dpt}`);
		return;
	}

	// Report
	if (isIPReportedRecently(srcIp)) return;
	await checkRateLimit();

	if (ABUSE_STATE.isBuffering) {
		if (BULK_REPORT_BUFFER.has(srcIp)) return;

		// Check buffer size limit to prevent memory overflow
		if (BULK_REPORT_BUFFER.size >= MAX_BUFFER_SIZE) {
			logger.warn(`${honeypot} -> Buffer full (${MAX_BUFFER_SIZE} IPs). Skipping ${srcIp} to prevent memory overflow.`);
			return;
		}

		BULK_REPORT_BUFFER.set(srcIp, { categories, timestamp, comment });
		await saveBufferToFile();
		return logger.success(`${honeypot} -> Queued ${srcIp} for bulk report (collected ${BULK_REPORT_BUFFER.size} IPs)`);
	}

	try {
		const { data: res } = await axiosService.post('/report', {
			ip: srcIp,
			categories,
			comment,
		});

		markIPAsReported(srcIp);
		await saveReportedIPs();

		logger.success(`${honeypot} -> Reported ${srcIp} [${dpt}/${proto}] | Categories: ${categories} | Abuse: ${res.data.abuseConfidenceScore}%`);
	} catch (err) {
		const status = err.response?.status;
		if (status === 429 && JSON.stringify(err.response?.data || {}).includes('Daily rate limit')) {
			if (!ABUSE_STATE.isLimited) {
				ABUSE_STATE.isLimited = true;
				ABUSE_STATE.isBuffering = true;
				ABUSE_STATE.sentBulk = false;
				LAST_RATELIMIT_LOG = Date.now();
				RATELIMIT_RESET = nextRateLimitReset();
				logger.info(`${honeypot} -> Daily API request limit for specified endpoint reached. Reports will be buffered until \`${RATELIMIT_RESET.toLocaleString()}\`. Bulk report will be sent the following day.`, { discord: true });
			}

			if (!BULK_REPORT_BUFFER.has(srcIp)) {
				BULK_REPORT_BUFFER.set(srcIp, { timestamp, categories, comment });
				await saveBufferToFile();
				logger.success(`${honeypot} -> Queued ${srcIp} for bulk report due to rate limit`);
			}
		} else {
			const failureMsg = `${honeypot} -> Failed to report ${srcIp} [${dpt}/${proto}]; ${err.response?.data?.errors ? JSON.stringify(err.response.data.errors) : err.message}`;
			status === 429 ? logger.info(failureMsg) : logger.error(failureMsg);
		}
	}
};

(async () => {
	banner();

	// Validate critical configuration
	if (config.MAIN.IP_REPORT_COOLDOWN < 15 * 60 * 1000) {
		logger.error('FATAL: IP_REPORT_COOLDOWN must be at least 15 minutes (900000 ms)');
		process.exit(1);
	}

	if (config.MAIN.DISCORD_WEBHOOK_ENABLED && !config.MAIN.DISCORD_WEBHOOK_URL) {
		logger.warn('DISCORD_WEBHOOK_ENABLED is true but DISCORD_WEBHOOK_URL is not set. Disabling webhooks.');
		config.MAIN.DISCORD_WEBHOOK_ENABLED = false;
	}

	// Log resolved paths in development mode
	if (SERVER_ID === 'development' && EXTENDED_LOGS) {
		const fs = require('node:fs');
		const validatePath = p => {
			try {
				return fs.existsSync(p) ? '✓' : '✗';
			} catch {
				return '?';
			}
		};

		const paths = {
			COWRIE_LOG_FILE: resolvePath(COWRIE_LOG_FILE),
			DIONAEA_LOG_FILE: resolvePath(DIONAEA_LOG_FILE),
			HONEYTRAP_LOG_FILE: resolvePath(HONEYTRAP_LOG_FILE),
			CACHE_FILE: resolvePath(CACHE_FILE),
			LOG_IP_HISTORY_DIR: resolvePath(LOG_IP_HISTORY_DIR),
		};

		logger.info('Development mode: Resolved file paths');
		logger.info(`  ${validatePath(paths.COWRIE_LOG_FILE)} COWRIE_LOG_FILE:    ${paths.COWRIE_LOG_FILE}`);
		logger.info(`  ${validatePath(paths.DIONAEA_LOG_FILE)} DIONAEA_LOG_FILE:   ${paths.DIONAEA_LOG_FILE}`);
		logger.info(`  ${validatePath(paths.HONEYTRAP_LOG_FILE)} HONEYTRAP_LOG_FILE: ${paths.HONEYTRAP_LOG_FILE}`);
		logger.info(`  ${validatePath(paths.CACHE_FILE)} CACHE_FILE:         ${paths.CACHE_FILE}`);
		logger.info(`  ${validatePath(paths.LOG_IP_HISTORY_DIR)} LOG_IP_HISTORY_DIR: ${paths.LOG_IP_HISTORY_DIR}`);
	}

	// Auto updates
	if (AUTO_UPDATE_ENABLED && AUTO_UPDATE_SCHEDULE && SERVER_ID !== 'development') {
		await require('./scripts/services/updates.js')();
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
		logger.info(`Found ${BULK_REPORT_BUFFER.size} IPs in buffer after restart. Sending bulk report...`);
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
			logger.info(`Caught ${signal}! Graceful shutdown started...`, { discord: true });

			try {
				for (const watcher of watchers) {
					if (typeof watcher?.flush === 'function') await watcher.flush();
					if (typeof watcher?.cleanup === 'function') watcher.cleanup();
					if (typeof watcher?.tail?.quit === 'function') await watcher.tail.quit();
				}
			} catch (err) {
				logger.error(`Error during shutdown: ${err.message}`);
			} finally {
				process.exit(0);
			}
		});
	});

	process.on('uncaughtException', err => {
		logger.error(`Uncaught exception: ${err.stack || err.message}`);
	});

	process.on('unhandledRejection', reason => {
		logger.error(`Unhandled rejection: ${reason}`);
	});

	// Summaries
	if (DISCORD_WEBHOOK_ENABLED && DISCORD_WEBHOOK_URL) await require('./scripts/services/summaries.js')();

	// Ready
	await logger.webhook(`[${repoSlug}](${repoUrl}) was successfully started!`, 0x59D267);
	process.send?.('ready');
})();

module.exports = reportIp;
const axios = require('./scripts/services/axios.js');
const { saveBufferToFile, loadBufferFromFile, sendBulkReport, BULK_REPORT_BUFFER } = require('./scripts/services/bulk.js');
const { loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported } = require('./scripts/services/cache.js');
const { refreshServerIPs, getServerIPs } = require('./scripts/services/ipFetcher.js');
const { name, version, repoFullUrl } = require('./scripts/repo.js');
const sendWebhook = require('./scripts/services/discordWebhooks.js');
const isLocalIP = require('./scripts/isLocalIP.js');
const log = require('./scripts/log.js');
const config = require('./config.js');
const formatTimestamp = require('./scripts/formatTimestamp.js');
const { ABUSEIPDB_API_KEY, SERVER_ID, EXTENDED_LOGS, AUTO_UPDATE_ENABLED, AUTO_UPDATE_SCHEDULE, DISCORD_WEBHOOKS_ENABLED, DISCORD_WEBHOOKS_URL } = config.MAIN;

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

			log(`✅ Rate limit reset. Next reset scheduled at ${RATELIMIT_RESET.toISOString()}`, 1, true);
		} else if (now - LAST_RATELIMIT_LOG >= RATE_LIMIT_LOG_INTERVAL) {
			const minutesLeft = Math.ceil((RATELIMIT_RESET.getTime() - now) / 60000);
			log(`⏳ Rate limit is still active. Collected ${BULK_REPORT_BUFFER.size} IPs. Waiting for reset in ${minutesLeft} minute(s) (${RATELIMIT_RESET.toISOString()})`, 0, true);
			LAST_RATELIMIT_LOG = now;
		}
	}
};

const reportIp = async (honeypot, { srcIp, dpt = 'N/A', proto = 'N/A', timestamp }, categories, comment) => {
	if (!srcIp) return log(`${honeypot} -> Missing source IP (srcIp)`, 3, true);

	const ips = getServerIPs();
	if (!Array.isArray(ips)) return log(`For some reason, 'ips' from 'getServerIPs()' is not an array. Received: ${ips}`, 3, true);

	if (ips.includes(srcIp)) return log(`Ignoring own IP address: PROTO=${proto?.toLowerCase()} SRC=${srcIp} DPT=${dpt}`, 0, true);
	if (isLocalIP(srcIp)) return log(`Ignoring local IP address: PROTO=${proto?.toLowerCase()} SRC=${srcIp} DPT=${dpt}`, 0, true);
	if (proto === 'UDP') {
		if (EXTENDED_LOGS) log(`Skipping UDP traffic: SRC=${srcIp} DPT=${dpt}`);
		return;
	}
	if (isIPReportedRecently(srcIp)) return;

	await checkRateLimit();

	if (ABUSE_STATE.isBuffering) {
		if (BULK_REPORT_BUFFER.has(srcIp)) return;

		BULK_REPORT_BUFFER.set(srcIp, { timestamp, categories, comment });
		await saveBufferToFile();
		log(`${honeypot} -> 💾 Queued ${srcIp} for bulk report (collected ${BULK_REPORT_BUFFER.size} IPs)`);
		return;
	}

	try {
		const { data: res } = await axios.post('https://api.abuseipdb.com/api/v2/report', new URLSearchParams({
			ip: srcIp,
			categories,
			comment,
			timestamp: formatTimestamp(timestamp || new Date().toISOString()),
		}), { headers: { Key: ABUSEIPDB_API_KEY } });

		markIPAsReported(srcIp);
		await saveReportedIPs();

		log(`${honeypot} -> ✅ Reported ${srcIp} [${dpt}/${proto}] | Categories: ${categories} | Score: ${res.data.abuseConfidenceScore}%`, 1);
	} catch (err) {
		const status = err.response?.status ?? 'unknown';
		if (status === 429 && JSON.stringify(err.response?.data || {}).includes('Daily rate limit')) {
			if (!ABUSE_STATE.isLimited) {
				ABUSE_STATE.isLimited = true;
				ABUSE_STATE.isBuffering = true;
				ABUSE_STATE.sentBulk = false;
				LAST_RATELIMIT_LOG = Date.now();
				RATELIMIT_RESET = nextRateLimitReset();
				log(`🚫 Daily AbuseIPDB limit reached. Buffering reports until ${RATELIMIT_RESET.toISOString()}`, 0, true);
			}

			if (BULK_REPORT_BUFFER.has(srcIp)) {
				log(`${honeypot} -> ⚠️ ${srcIp} is already in buffer, skipping`);
				return;
			}

			BULK_REPORT_BUFFER.set(srcIp, { timestamp, categories, comment });
			await saveBufferToFile();
			log(`${honeypot} -> ✋ Queued ${srcIp} for bulk report due to rate limit`);
		} else {
			log(`Failed to report ${srcIp} [${dpt}/${proto}]; ${err.response?.data?.errors ? JSON.stringify(err.response.data.errors) : err.message}`, status === 429 ? 0 : 3);
		}
	}
};

(async () => {
	log(`🚀 T-Pot AbuseIPDB Reporter v${version} (https://github.com/sefinek/T-Pot-AbuseIPDB-Reporter)`);

	// Auto updates
	if (AUTO_UPDATE_ENABLED && AUTO_UPDATE_SCHEDULE && SERVER_ID !== 'development') {
		await require('./scripts/services/updates.js')();
	} else {
		await require('./scripts/services/version.js')();
	}

	// Bulk
	await loadReportedIPs();
	await loadBufferFromFile();

	if (BULK_REPORT_BUFFER.size > 0 && !ABUSE_STATE.isLimited) {
		log(`Found ${BULK_REPORT_BUFFER.size} IPs in buffer after restart. Sending bulk report...`);
		await sendBulkReport();
	}

	// Fetch IPs
	log('Fetching public IP addresses from api.sefinek.net...');
	await refreshServerIPs();
	log(`Retrieved ${getServerIPs()?.length} IP address(es) for this machine`, 1);

	// Watch
	require('./honeypots/dionaea.js')(reportIp);
	require('./honeypots/honeytrap.js')(reportIp);
	require('./honeypots/cowrie.js')(reportIp);

	// Summaries
	if (DISCORD_WEBHOOKS_ENABLED && DISCORD_WEBHOOKS_URL) await require('./scripts/services/summaries.js')();

	// Ready
	await sendWebhook(`[${name}](${repoFullUrl}) has been successfully started on the device \`${SERVER_ID}\`.`, 0x59D267);
	log(`T-Pot AbuseIPDB Reporter has started${SERVER_ID ? ` on \`${SERVER_ID}\`` : '!'}`, 1);
	process.send?.('ready');
})();

module.exports = reportIp;
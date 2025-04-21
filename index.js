const axios = require('./services/axios.js');
const { saveBufferToFile, loadBufferFromFile, sendBulkReport, BULK_REPORT_BUFFER } = require('./services/bulk.js');
const { refreshServerIPs, getServerIPs } = require('./services/ipFetcher.js');
const { loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported } = require('./services/cache.js');
const log = require('./utils/log.js');
const config = require('./config.js');
const { version } = require('./package.json');
const formatTimestamp = require('./utils/formatTimestamp.js');
const { ABUSEIPDB_API_KEY, SERVER_ID, DISCORD_WEBHOOKS_ENABLED, DISCORD_WEBHOOKS_URL } = config.MAIN;

const ABUSE_STATE = { isLimited: false, isBuffering: false, sentBulk: false };
const RATE_LIMIT_LOG_INTERVAL = 10 * 60 * 1000;
const BUFFER_STATS_INTERVAL = 5 * 60 * 1000;

const nextRateLimitReset = () => {
	const now = new Date();
	return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 1));
};

let LAST_RATELIMIT_LOG = 0, LAST_STATS_LOG = 0, RATELIMIT_RESET = nextRateLimitReset();

const checkRateLimit = () => {
	const now = Date.now();
	if (now - LAST_STATS_LOG >= BUFFER_STATS_INTERVAL && BULK_REPORT_BUFFER.size > 0) LAST_STATS_LOG = now;

	if (ABUSE_STATE.isLimited) {
		if (now >= RATELIMIT_RESET.getTime()) {
			ABUSE_STATE.isLimited = false;
			ABUSE_STATE.isBuffering = false;
			if (!ABUSE_STATE.sentBulk && BULK_REPORT_BUFFER.size > 0) sendBulkReport();
			RATELIMIT_RESET = nextRateLimitReset();
			ABUSE_STATE.sentBulk = false;

			log(0, `✅ Rate limit reset. Next reset scheduled at ${RATELIMIT_RESET.toISOString()}`, 1);
		} else if (now - LAST_RATELIMIT_LOG >= RATE_LIMIT_LOG_INTERVAL) {
			const minutesLeft = Math.ceil((RATELIMIT_RESET.getTime() - now) / 60000);
			log(0, `⏳ Rate limit is still active. Collected ${BULK_REPORT_BUFFER.size} IPs. Waiting for reset in ${minutesLeft} minute(s) (${RATELIMIT_RESET.toISOString()})`, 1);
			LAST_RATELIMIT_LOG = now;
		}
	}
};

const reportIp = async (honeypot, { srcIp, dpt = 'N/A', service = 'N/A', timestamp }, categories, comment) => {
	if (!srcIp) return log(2, `${honeypot} -> ⛔ Missing source IP (srcIp)`, 1);

	if (getServerIPs().includes(srcIp)) return;
	if (isIPReportedRecently(srcIp)) return;

	checkRateLimit();

	if (ABUSE_STATE.isBuffering) {
		if (BULK_REPORT_BUFFER.has(srcIp)) return;

		BULK_REPORT_BUFFER.set(srcIp, { timestamp, categories, comment });
		saveBufferToFile();
		log(0, `${honeypot} -> 💾 Queued ${srcIp} for bulk report (collected ${BULK_REPORT_BUFFER.size} IPs)`);
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
		saveReportedIPs();
		log(0, `${honeypot} -> ✅ Reported ${srcIp} [${dpt}/${service}] | Categories: ${categories} | Score: ${res.data.abuseConfidenceScore}%`);
	} catch (err) {
		if (err.response?.status === 429 && JSON.stringify(err.response?.data || {}).includes('Daily rate limit')) {
			if (!ABUSE_STATE.isLimited) {
				ABUSE_STATE.isLimited = true;
				ABUSE_STATE.isBuffering = true;
				ABUSE_STATE.sentBulk = false;
				LAST_RATELIMIT_LOG = Date.now();
				RATELIMIT_RESET = nextRateLimitReset();
				log(0, `🚫 Daily AbuseIPDB limit reached. Buffering reports until ${RATELIMIT_RESET.toISOString()}`, 1);
			}

			if (BULK_REPORT_BUFFER.has(srcIp)) {
				log(0, `${honeypot} -> ⚠️ ${srcIp} is already in buffer, skipping`);
				return;
			}

			BULK_REPORT_BUFFER.set(srcIp, { timestamp, categories, comment });
			saveBufferToFile();

			log(0, `${honeypot} -> ✋ Queued ${srcIp} for bulk report due to rate limit`);
		} else {
			const status = err.response?.status ?? 'unknown';
			log(
				status === 429 ? 0 : 2,
				`${honeypot} -> ❌ Failed to report ${srcIp} [${dpt}/${service}];\n${err.response?.data?.errors ? JSON.stringify(err.response.data.errors) : err.message}`,
				status === 429 ? 0 : 1
			);
		}
	}
};

(async () => {
	log(0, `🚀 T-Pot AbuseIPDB Reporter v${version} (https://github.com/sefinek/T-Pot-AbuseIPDB-Reporter)`);

	loadReportedIPs();
	loadBufferFromFile();

	if (BULK_REPORT_BUFFER.size > 0 && !ABUSE_STATE.isLimited) {
		log(0, `📤 Found ${BULK_REPORT_BUFFER.size} IPs in buffer after restart. Sending bulk report...`);
		await sendBulkReport();
	}

	if (DISCORD_WEBHOOKS_ENABLED && DISCORD_WEBHOOKS_URL) await require('./services/summaries.js')();

	log(0, '🌐 Fetching public IP addresses from api.sefinek.net...');
	await refreshServerIPs();
	log(0, `✅ Retrieved ${getServerIPs()?.length} IP address(es) for this machine`);

	require('./data/dionaea.js')(reportIp);
	require('./data/honeytrap.js')(reportIp);
	require('./data/cowrie.js')(reportIp);

	if (SERVER_ID !== 'development') log(0, `T-Pot AbuseIPDB Reporter has started${SERVER_ID ? ` on \`${SERVER_ID}\`` : '!'}`, 2);
	process.send?.('ready');
})();

module.exports = reportIp;
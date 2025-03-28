const FormData = require('form-data');
const log = require('./utils/log.js');
const { loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported } = require('./services/cache.js');
const axios = require('./services/axios.js');
const { refreshServerIPs, getServerIPs } = require('./services/ipFetcher.js');
const config = require('./config.js');
const { version } = require('./package.json');
const discordWebhooks = require('./services/discord.js');
const formatTimestamp = require('./utils/formatTimestamp.js');

const { ABUSEIPDB_API_KEY, SERVER_ID, AUTO_UPDATE_ENABLED, AUTO_UPDATE_SCHEDULE, DISCORD_WEBHOOKS_ENABLED, DISCORD_WEBHOOKS_URL } = config.MAIN;

const abuseState = { isLimited: false, isBuffering: false, sentBulk: false };
const bulkReportBuffer = new Map();

const RATE_LIMIT_LOG_INTERVAL = 10 * 60 * 1000;
let lastRateLimitLog = 0;
let rateLimitReset = (() => {
	const now = new Date();
	return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 1));
})();

const sendBulkReport = async () => {
	if (!bulkReportBuffer.size) return;

	const lines = ['IP,Categories,ReportDate,Comment'];
	for (const [ip, entry] of bulkReportBuffer.entries()) {
		const line = [
			ip,
			`"${entry.categories}"`,
			new Date(entry.timestamp || Date.now()).toISOString(),
			`"${entry.comment.replace(/\n/g, ' ').substring(0, 1024)}"`,
		].join(',');
		lines.push(line);
	}

	try {
		const payload = lines.join('\n');
		const form = new FormData();
		form.append('csv', Buffer.from(payload), {
			filename: 'report.csv',
			contentType: 'text/csv',
		});

		const { data } = await axios.post('https://api.abuseipdb.com/api/v2/bulk-report', form, {
			headers: {
				Key: ABUSEIPDB_API_KEY,
				...form.getHeaders(),
			},
		});

		const saved = data?.data?.savedReports ?? 0;
		const failed = data?.data?.invalidReports?.length ?? 0;

		log(0, `[${new Date().toISOString()}] Sent bulk report to AbuseIPDB: ${saved} accepted, ${failed} rejected`);
		if (failed > 0) {
			data.data.invalidReports.forEach((fail) => {
				log(1, `Rejected in bulk report [Row ${fail.rowNumber}] ${fail.input} -> ${fail.error}`);
			});
		}

		for (const ip of bulkReportBuffer.keys()) markIPAsReported(ip);
		saveReportedIPs();
		bulkReportBuffer.clear();
		abuseState.sentBulk = true;
	} catch (err) {
		log(1, `❌ Failed to send bulk report to AbuseIPDB: ${err.stack}`);
	}
};

const checkRateLimit = () => {
	const now = Date.now();
	if (abuseState.isLimited) {
		if (now >= rateLimitReset.getTime()) {
			abuseState.isLimited = false;
			abuseState.isBuffering = false;

			if (!abuseState.sentBulk && bulkReportBuffer.size > 0) sendBulkReport();

			const current = new Date();
			rateLimitReset = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth(), current.getUTCDate() + 1, 0, 1));
			abuseState.sentBulk = false;
			log(0, `✅ Rate limit reset. Next reset scheduled at ${rateLimitReset.toISOString()}`);
		} else if (now - lastRateLimitLog >= RATE_LIMIT_LOG_INTERVAL) {
			const minutesLeft = Math.ceil((rateLimitReset.getTime() - now) / 60000);
			log(0, `⏳ AbuseIPDB rate limit active. Waiting for reset in ${minutesLeft} minutes (${rateLimitReset.toISOString()})`);
			lastRateLimitLog = now;
		}
	}
	return abuseState.isLimited;
};

const reportToAbuseIPDb = async (honeypot, { srcIp, dpt = 'N/A', service = 'N/A', timestamp }, categories, comment) => {
	if (checkRateLimit()) return false;
	if (!srcIp) return log(2, `${honeypot} -> ⛔ Missing source IP (srcIp)`);
	if (getServerIPs().includes(srcIp)) return;
	if (isIPReportedRecently(srcIp)) return;

	if (abuseState.isBuffering) {
		bulkReportBuffer.set(srcIp, { timestamp, categories, comment });
		log(0, `${honeypot} -> ⏳ Queued ${srcIp} for bulk report later`);
		return true;
	}

	try {
		const { data: res } = await axios.post('https://api.abuseipdb.com/api/v2/report', new URLSearchParams({
			ip: srcIp,
			categories,
			comment,
			timestamp: formatTimestamp(timestamp || new Date().toISOString()),
		}), { headers: { Key: ABUSEIPDB_API_KEY } });

		log(0, `${honeypot} -> ✅ Reported ${srcIp} [${dpt}/${service}] | Categories: ${categories} | Score: ${res.data.abuseConfidenceScore}%`);
		markIPAsReported(srcIp);
		saveReportedIPs();
		return true;
	} catch (err) {
		if (err.response?.status === 429 && JSON.stringify(err.response?.data || {}).includes('Daily rate limit')) {
			if (!abuseState.isLimited) {
				abuseState.isLimited = true;
				abuseState.isBuffering = true;
				abuseState.sentBulk = false;
				lastRateLimitLog = Date.now();
				const now = new Date();
				rateLimitReset = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 1));
				log(1, `🚫 Daily AbuseIPDB limit reached. Buffering reports until ${rateLimitReset.toISOString()}`);
			}

			bulkReportBuffer.set(srcIp, { timestamp, categories, comment });
			log(0, `${honeypot} -> ⏳ Queued ${srcIp} for bulk report due to rate limit`);
		} else {
			const details = JSON.stringify(err.response?.data?.errors || err.response?.data);
			log(err.response?.status === 429 ? 0 : 2, `${honeypot} -> ❌ Failed to report ${srcIp} [${dpt}/${service}]: ${details}\n${err.message}`);
		}
		return false;
	}
};

(async () => {
	log(0, `🚀 T-Pot AbuseIPDB Reporter v${version} started (https://github.com/sefinek/T-Pot-AbuseIPDB-Reporter)`);

	loadReportedIPs();

	log(0, '🌐 Fetching public IP addresses from api.sefinek.net...');
	await refreshServerIPs();
	log(0, `✅ Retrieved ${getServerIPs()?.length} IP address(es) for this machine`);

	require('./data/dionaea.js')(reportToAbuseIPDb);
	require('./data/honeytrap.js')(reportToAbuseIPDb);
	require('./data/cowrie.js')(reportToAbuseIPDb);

	if (AUTO_UPDATE_ENABLED && AUTO_UPDATE_SCHEDULE && SERVER_ID !== 'development') await require('./services/updates.js')();
	if (DISCORD_WEBHOOKS_ENABLED && DISCORD_WEBHOOKS_URL) await require('./services/summaries.js')();

	if (SERVER_ID !== 'development') await discordWebhooks(0, `T-Pot AbuseIPDB Reporter has started on \`${SERVER_ID}\``);
	process.send?.('ready');
})();

module.exports = reportToAbuseIPDb;
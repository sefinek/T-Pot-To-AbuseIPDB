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

let abuseIPDBRateLimited = false, bulkMode = false;
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

		log(0, `Bulk report sent: ${saved} saved, ${failed} rejected`);
		if (failed > 0) {
			data.data.invalidReports.forEach((fail) => {
				log(1, `Bulk report error: [Row ${fail.rowNumber}] ${fail.input} => ${fail.error}`);
			});
		}

		for (const ip of bulkReportBuffer.keys()) markIPAsReported(ip);
		saveReportedIPs();
		bulkReportBuffer.clear();
	} catch (err) {
		log(1, `Bulk report failed: ${err.message}`);
	}
};

const checkRateLimit = () => {
	const now = Date.now();
	if (abuseIPDBRateLimited) {
		if (now >= rateLimitReset.getTime()) {
			abuseIPDBRateLimited = false;
			bulkMode = false;

			if (bulkReportBuffer.size > 0) sendBulkReport();

			const current = new Date();
			rateLimitReset = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth(), current.getUTCDate() + 1, 0, 1));
			log(0, `Rate limit state reset. Next reset at ${rateLimitReset.toISOString()}`);
		} else if (now - lastRateLimitLog >= RATE_LIMIT_LOG_INTERVAL) {
			const minutesLeft = Math.ceil((rateLimitReset.getTime() - now) / 60000);
			log(0, `AbuseIPDB rate limit active. Waiting for reset at ${rateLimitReset.toISOString()} (in ${minutesLeft} min)`);
			lastRateLimitLog = now;
		}
	}
	return abuseIPDBRateLimited;
};

const reportToAbuseIPDb = async (honeypot, { srcIp, dpt = 'N/A', service = 'N/A', timestamp }, categories, comment) => {
	if (checkRateLimit()) return false;
	if (!srcIp) return log(2, `${honeypot} -> Missing source IP (srcIp)`);
	if (getServerIPs().includes(srcIp)) return;
	if (isIPReportedRecently(srcIp)) return;

	if (bulkMode) {
		bulkReportBuffer.set(srcIp, { timestamp, categories, comment });
		log(0, `${honeypot} -> Buffered ${srcIp} for later bulk report`);
		return true;
	}

	try {
		const { data: res } = await axios.post('https://api.abuseipdb.com/api/v2/report', new URLSearchParams({
			ip: srcIp,
			categories,
			comment,
			timestamp: formatTimestamp(timestamp || new Date().toISOString()),
		}), { headers: { Key: ABUSEIPDB_API_KEY } });

		log(0, `${honeypot} -> Reported ${srcIp} [${dpt}/${service}]; Categories: ${categories}; Abuse: ${res.data.abuseConfidenceScore}%`);
		markIPAsReported(srcIp);
		saveReportedIPs();
		return true;
	} catch (err) {
		if (err.response?.status === 429 && JSON.stringify(err.response?.data || {}).includes('Daily rate limit')) {
			if (!abuseIPDBRateLimited) {
				abuseIPDBRateLimited = true;
				bulkMode = true;
				lastRateLimitLog = Date.now();
				const now = new Date();
				rateLimitReset = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 1));
				log(1, `Daily limit reached for AbuseIPDB! Buffering reports until ${rateLimitReset.toISOString()}`);
			}

			bulkReportBuffer.set(srcIp, { timestamp, categories, comment });
			log(0, `${honeypot} -> Buffered ${srcIp} for later bulk report`);
		} else {
			const details = JSON.stringify(err.response?.data?.errors || err.response?.data || err.message);
			log(err.response?.status === 429 ? 0 : 2, `${honeypot} -> Failed to report ${srcIp} [${dpt}/${service}]; ${err.message}\n${details}`);
		}
		return false;
	}
};

(async () => {
	log(0, `Version ${version} - https://github.com/sefinek/T-Pot-AbuseIPDB-Reporter`);

	loadReportedIPs();

	log(0, 'Trying to fetch your IPv4 and IPv6 address from api.sefinek.net...');
	await refreshServerIPs();
	log(0, `Fetched ${getServerIPs()?.length} of your IP addresses`);

	require('./data/dionaea.js')(reportToAbuseIPDb);
	require('./data/honeytrap.js')(reportToAbuseIPDb);
	require('./data/cowrie.js')(reportToAbuseIPDb);

	if (AUTO_UPDATE_ENABLED && AUTO_UPDATE_SCHEDULE && SERVER_ID !== 'development') await require('./services/updates.js')();
	if (DISCORD_WEBHOOKS_ENABLED && DISCORD_WEBHOOKS_URL) await require('./services/summaries.js')();

	if (SERVER_ID !== 'development') await discordWebhooks(0, `T-Pot AbuseIPDB Reporter has started on \`${SERVER_ID}\``);
	process.send?.('ready');
})();

module.exports = reportToAbuseIPDb;
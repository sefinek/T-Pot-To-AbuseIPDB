const fs = require('node:fs');
const path = require('node:path');
const FormData = require('form-data');
const axios = require('./services/axios.js');
const { refreshServerIPs, getServerIPs } = require('./services/ipFetcher.js');
const { loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported } = require('./services/cache.js');
const log = require('./utils/log.js');
const config = require('./config.js');
const { version } = require('./package.json');
const discordWebhooks = require('./services/discord.js');
const formatTimestamp = require('./utils/formatTimestamp.js');

const { ABUSEIPDB_API_KEY, SERVER_ID, DEBUG_MODE, DISCORD_WEBHOOKS_ENABLED, DISCORD_WEBHOOKS_URL } = config.MAIN;

const BULK_REPORT_BUFFER = new Map();
const BUFFER_FILE = path.join(__dirname, 'bulk-report-buffer.csv');
const ABUSE_STATE = { isLimited: false, isBuffering: false, sentBulk: false };
const RATE_LIMIT_LOG_INTERVAL = 10 * 60 * 1000;
const BUFFER_STATS_INTERVAL = 5 * 60 * 1000;

let LAST_RATELIMIT_LOG = 0;
let LAST_STATS_LOG = 0;
let RATELIMIT_RESET = (() => {
	const now = new Date();
	return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 1));
})();

const saveBufferToFile = () => {
	if (!BULK_REPORT_BUFFER.size) return;
	const lines = [];
	for (const [ip, entry] of BULK_REPORT_BUFFER.entries()) {
		const safeComment = entry.comment.replace(/"/g, '""').replace(/\n/g, '\\n').substring(0, 1024);
		lines.push([
			`"${ip}"`,
			`"${Array.isArray(entry.categories) ? entry.categories.join(',') : entry.categories}"`,
			new Date(entry.timestamp).toISOString(),
			`"${safeComment}"`,
		].join(','));
	}
	fs.writeFileSync(BUFFER_FILE, lines.join('\n') + '\n');
	log(0, `💾 Saved ${BULK_REPORT_BUFFER.size} IPs to buffer file (${BUFFER_FILE})`);
};

const loadBufferFromFile = () => {
	if (!fs.existsSync(BUFFER_FILE)) return;
	const lines = fs.readFileSync(BUFFER_FILE, 'utf-8').split('\n');
	let loaded = 0;
	for (const line of lines) {
		if (!line.trim()) continue;
		const match = line.match(/^"([^\\"]+)","([^\\"]+)",([^,]+),"([\s\S]*)"$/);
		if (!match) continue;
		const [, ip, categories, timestamp, comment] = match;
		BULK_REPORT_BUFFER.set(ip, {
			categories: categories.split(',').map(c => c.trim()),
			timestamp: new Date(timestamp).getTime(),
			comment: comment.replace(/\\n/g, '\n'),
		});
		loaded++;
	}
	fs.unlinkSync(BUFFER_FILE);
	log(0, `📂 Loaded ${loaded} IPs from buffer file (${BUFFER_FILE})`);
};

const sendBulkReport = async () => {
	if (!BULK_REPORT_BUFFER.size) return;

	const lines = ['IP,Categories,ReportDate,Comment'];
	for (const [ip, entry] of BULK_REPORT_BUFFER.entries()) {
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

		log(0, `🤮 Sent bulk report to AbuseIPDB: ${saved} accepted, ${failed} rejected`);
		if (failed > 0) {
			data.data.invalidReports.forEach(fail => {
				log(1, `Rejected in bulk report [Row ${fail.rowNumber}] ${fail.input} -> ${fail.error}`);
			});
		}

		for (const ip of BULK_REPORT_BUFFER.keys()) markIPAsReported(ip);
		saveReportedIPs();
		BULK_REPORT_BUFFER.clear();
		if (fs.existsSync(BUFFER_FILE)) fs.unlinkSync(BUFFER_FILE);
		log(0, '🧹 Cleared buffer after bulk report. Buffer file deleted.');
		ABUSE_STATE.sentBulk = true;
	} catch (err) {
		log(1, `❌ Failed to send bulk report to AbuseIPDB: ${err.stack}`);
	}
};

const checkRateLimit = () => {
	const now = Date.now();
	if (now - LAST_STATS_LOG >= BUFFER_STATS_INTERVAL && BULK_REPORT_BUFFER.size > 0) {
		log(0, `📊 Buffer size: ${BULK_REPORT_BUFFER.size} IP(s) currently queued`);
		LAST_STATS_LOG = now;
	}

	if (ABUSE_STATE.isLimited) {
		if (now >= RATELIMIT_RESET.getTime()) {
			ABUSE_STATE.isLimited = false;
			ABUSE_STATE.isBuffering = false;
			if (!ABUSE_STATE.sentBulk && BULK_REPORT_BUFFER.size > 0) sendBulkReport();

			const current = new Date();
			RATELIMIT_RESET = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth(), current.getUTCDate() + 1, 0, 1));
			ABUSE_STATE.sentBulk = false;
			log(0, `✅ Rate limit reset. Next reset scheduled at ${RATELIMIT_RESET.toISOString()}`);
		} else if (now - LAST_RATELIMIT_LOG >= RATE_LIMIT_LOG_INTERVAL) {
			const minutesLeft = Math.ceil((RATELIMIT_RESET.getTime() - now) / 60000);
			log(0, `⏳ AbuseIPDB rate limit is active. Collected ${BULK_REPORT_BUFFER.size} IPs. Waiting for reset in ${minutesLeft} minute(s) (${RATELIMIT_RESET.toISOString()})`);
			LAST_RATELIMIT_LOG = now;
		}
	}
};

const reportToAbuseIPDb = async (honeypot, { srcIp, dpt = 'N/A', service = 'N/A', timestamp }, categories, comment) => {
	if (!srcIp) return log(2, `${honeypot} -> ⛔ Missing source IP (srcIp)`);
	if (getServerIPs().includes(srcIp)) return;

	if (DEBUG_MODE) log(0, `${honeypot} -> Checking if ${srcIp} was reported recently...`);
	if (isIPReportedRecently(srcIp)) {
		if (DEBUG_MODE) log(0, `${honeypot} -> Skipping ${srcIp}, already reported recently`);
		return;
	}

	checkRateLimit();

	if (ABUSE_STATE.isBuffering) {
		if (BULK_REPORT_BUFFER.has(srcIp)) {
			if (DEBUG_MODE) log(0, `${honeypot} -> ⚠️ ${srcIp} is already in buffer, skipping`);
			return;
		}

		BULK_REPORT_BUFFER.set(srcIp, { timestamp, categories, comment });
		saveBufferToFile();
		log(0, `${honeypot} -> ⏳ Queued ${srcIp} for bulk report (buffering)`);
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
				const now = new Date();
				RATELIMIT_RESET = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 1));
				log(1, `🚫 Daily AbuseIPDB limit reached. Buffering reports until ${RATELIMIT_RESET.toISOString()}`);
			}

			if (BULK_REPORT_BUFFER.has(srcIp)) {
				log(0, `${honeypot} -> ⚠️ ${srcIp} is already in buffer, skipping`);
				return;
			}

			BULK_REPORT_BUFFER.set(srcIp, { timestamp, categories, comment });
			saveBufferToFile();
			log(0, `${honeypot} -> ⏳ Queued ${srcIp} for bulk report due to rate limit`);
		} else {
			const details = JSON.stringify(err.response?.data?.errors || err.response?.data);
			log(err.response?.status === 429 ? 0 : 2, `${honeypot} -> ❌ Failed to report ${srcIp} [${dpt}/${service}]: ${details}\n${err.message}`);
		}
	}
};

(async () => {
	log(0, `🚀 T-Pot AbuseIPDB Reporter v${version} (https://github.com/sefinek/T-Pot-AbuseIPDB-Reporter)`);

	loadReportedIPs();
	loadBufferFromFile();

	if (BULK_REPORT_BUFFER.size > 0 && !ABUSE_STATE.isLimited) {
		log(0, `📤 Found ${BULK_REPORT_BUFFER.size} IP(s) in buffer after restart. Sending bulk report...`);
		await sendBulkReport();
	}

	// Tests
	// ABUSE_STATE.isLimited = true;
	// ABUSE_STATE.isBuffering = true;

	if (DISCORD_WEBHOOKS_ENABLED && DISCORD_WEBHOOKS_URL) await require('./services/summaries.js')();

	log(0, '🌐 Fetching public IP addresses from api.sefinek.net...');
	await refreshServerIPs();
	log(0, `✅ Retrieved ${getServerIPs()?.length} IP address(es) for this machine`);

	require('./data/dionaea.js')(reportToAbuseIPDb);
	require('./data/honeytrap.js')(reportToAbuseIPDb);
	require('./data/cowrie.js')(reportToAbuseIPDb);

	if (SERVER_ID !== 'development') await discordWebhooks(0, `T-Pot AbuseIPDB Reporter has started on \`${SERVER_ID}\``);
	process.send?.('ready');
})();

module.exports = reportToAbuseIPDb;
//
//   Copyright 2025 (c) by Sefinek All rights reserved.
//                 https://sefinek.net
//

const log = require('./utils/log.js');
const { loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported } = require('./services/cache.js');
const axios = require('./services/axios.js');
const { refreshServerIPs, getServerIPs } = require('./services/ipFetcher.js');
const config = require('./config.js');
const { version } = require('./package.json');
const discordWebhooks = require('./services/discord.js');
const formatTimestamp = require('./utils/formatTimestamp.js');

const { ABUSEIPDB_API_KEY, SERVER_ID, AUTO_UPDATE_ENABLED, AUTO_UPDATE_SCHEDULE, DISCORD_WEBHOOKS_ENABLED, DISCORD_WEBHOOKS_URL } = config.MAIN;

const reportToAbuseIPDb = async (honeypot, { srcIp, dpt = 'N/A', service = 'N/A', timestamp }, categories, comment) => {
	if (!srcIp) return log(2, `${honeypot} -> Missing source IP (srcIp)`);
	if (getServerIPs().includes(srcIp)) return log(0, `${honeypot} -> Ignoring own IP`);

	if (isIPReportedRecently(srcIp)) return;

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
		const details = JSON.stringify(err.response?.data?.errors || err.response?.data || err.message);
		log(2, `${honeypot} -> Failed to report ${srcIp} [${dpt}/${service}]; ${err.message}\n${details}`);
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
	// require('./data/cowrie.js')(reportToAbuseIPDb);

	if (AUTO_UPDATE_ENABLED && AUTO_UPDATE_SCHEDULE && SERVER_ID !== 'development') await require('./services/updates.js')();
	if (DISCORD_WEBHOOKS_ENABLED && DISCORD_WEBHOOKS_URL) await require('./services/summaries.js')();

	if (SERVER_ID !== 'development') await discordWebhooks(0, `T-Pot AbuseIPDB Reporter has started on \`${SERVER_ID}\``);
	process.send?.('ready');
})();

module.exports = reportToAbuseIPDb;

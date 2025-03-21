const { networkInterfaces } = require('node:os');
const https = require('node:https');
const { CronJob } = require('cron');
const { get } = require('./axios.js');
const isLocalIP = require('../utils/isLocalIP.js');
const log = require('../utils/log.js');
const discordWebhooks = require('./discord.js');
const { IP_REFRESH_SCHEDULE, IPv6_SUPPORT } = require('../config.js').MAIN;

const ipAddresses = new Set();
let ipv6ErrorCount = 0, ipv6ErrorLogged = false;
const IPv6Failed = 'It looks like your ISP hasn\'t assigned you any IPv6 address. I won\'t attempt to fetch it again.';

const fetchIPAddress = async family => {
	if (family === 6 && (ipv6ErrorLogged || !IPv6_SUPPORT)) return;

	try {
		const { data } = await get('https://api.sefinek.net/api/v2/ip', {
			httpsAgent: new https.Agent({ family }),
		});

		if (data?.success && data?.message) {
			ipAddresses.add(data.message);

			if (family === 6) {
				if (ipv6ErrorCount > 0) {
					const IPv6Success = `Uh, it looks like IPv6 has started working! It only succeeded after ${ipv6ErrorCount} attempts.`;
					log(0, IPv6Success);
					await discordWebhooks(4, IPv6Success);
				}

				ipv6ErrorCount = 0;
			}
		} else {
			log(2, `Unexpected API response: ${JSON.stringify(data)}`);
		}
	} catch (err) {
		log(2, `Error fetching IPv${family} address: ${err.message}`);

		if (family === 6 && err.code === 'ENOENT') {
			ipv6ErrorCount++;

			if (ipv6ErrorCount >= 6 && !ipv6ErrorLogged) {
				ipv6ErrorLogged = true;
				log(0, IPv6Failed);
				await discordWebhooks(4, IPv6Failed);
			} else {
				await new Promise(resolve => setTimeout(resolve, 4000));
				await fetchIPAddress(6);
			}
		}
	}
};

const fetchLocalIPs = () => {
	for (const iface of Object.values(networkInterfaces()).flat()) {
		if (iface && !iface.internal && iface.address && !isLocalIP(iface.address)) {
			ipAddresses.add(iface.address);
		}
	}
};

const refreshServerIPs = async () => {
	await Promise.all([fetchIPAddress(4), fetchIPAddress(6)]);
	fetchLocalIPs();
};

(async () => {
	new CronJob(IP_REFRESH_SCHEDULE || '0 */6 * * *', refreshServerIPs, null, true, 'UTC');
})();

module.exports = {
	refreshServerIPs,
	getServerIPs: () => [...ipAddresses],
};
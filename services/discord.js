const axios = require('axios');
const log = require('../utils/log.js');
const { repoFull } = require('../utils/repo.js');
const { SERVER_ID, DISCORD_WEBHOOKS_ENABLED, DISCORD_WEBHOOKS_URL } = require('../config.js').MAIN;

const TYPES = {
	0: { color: 0x60D06D },
	1: { color: 0xFFB02E },
	2: { color: 0xF92F60 },
};

module.exports = async (id, description) => {
	if (!DISCORD_WEBHOOKS_ENABLED || !DISCORD_WEBHOOKS_URL) return;

	const logType = TYPES[id];
	if (!logType) return log(1, 'Invalid log type ID provided!');

	const config = {
		method: 'POST',
		url: DISCORD_WEBHOOKS_URL,
		headers: { 'Content-Type': 'application/json' },
		data: {
			embeds: [{
				description: description.replace(/(\b\w+=)/g, '**$1**'),
				color: logType.color,
				footer: {
					text: `${SERVER_ID ? `${SERVER_ID} • ` : ''}${repoFull}`,
				},
				timestamp: new Date().toISOString(),
			}],
		},
	};

	try {
		const res = await axios(config);
		if (res.status !== 204) log(1, 'Failed to deliver Discord Webhook');
	} catch (err) {
		log(2, `Failed to send Discord Webhook. ${err.stack}`);
	}
};
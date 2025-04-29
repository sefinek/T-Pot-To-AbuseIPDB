const axios = require('axios');
const { repoFull } = require('../utils/repo.js');
const { SERVER_ID, DISCORD_WEBHOOKS_ENABLED, DISCORD_WEBHOOKS_URL } = require('../config.js').MAIN;

const COLORS = {
	0: 0x59D267, // Green
	1: 0xFFA91B, // Orange
	2: 0xFF0F31, // Red
	3: 0x266CFB, // Blue
};

module.exports = async (id, description, log) => {
	if (!DISCORD_WEBHOOKS_ENABLED || !DISCORD_WEBHOOKS_URL) return;

	const config = {
		method: 'POST',
		url: DISCORD_WEBHOOKS_URL,
		headers: { 'Content-Type': 'application/json' },
		data: {
			embeds: [{
				description: description
					.replace(/\p{Emoji_Presentation}/gu, '')
					.replace(/(\b\w+=)/g, '**$1**')
					.trim(),
				color: COLORS[id] || 0x070709,
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
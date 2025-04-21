const sendWebhook = require('../services/discordWebhooks.js');

const levels = {
	0: { method: 'log' },
	1: { method: 'warn' },
	2: { method: 'error' },
};

module.exports = (level, msg, discord = 0) => {
	if (discord !== 2) {
		const { method } = levels[level] || levels[0];
		console[method](`${msg}`);
	}

	if (discord === 1 || discord === 2) sendWebhook(level, msg).catch(console.error);
};
const sendWebhook = require('../services/discordWebhooks.js');

const levels = {
	0: { method: 'log' },
	1: { method: 'warn' },
	2: { method: 'error' },
};

module.exports = (level, msg, discord = 0) => {
	const { method } = levels[level] || { method: 'log' };
	console[method](`${msg}`);

	if (discord) sendWebhook(level, msg).catch(console.error);
};
const levels = {
	0: { method: 'log' },
	1: { method: 'warn' },
	2: { method: 'error' },
};

module.exports = (level, msg, webhookFail = false) => {
	const { method } = levels[level] || { method: 'log' };
	console[method](`${msg}`);

	if (level >= 1 && !webhookFail) {
		const discordWebhooks = require('../services/discord.js');
		discordWebhooks(level, msg).catch(console.error);
	}
};
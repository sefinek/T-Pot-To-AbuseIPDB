const sendWebhook = require('../services/discordWebhooks.js');

const METHODS = ['log', 'warn', 'error'];

const logger = (level = 0, msg, discord = 0) => {
	if (discord !== 2) console[METHODS[level] || 'log'](msg);

	if (discord) {
		sendWebhook(level, msg, logger).catch(console.error);
	}
};

module.exports = logger;
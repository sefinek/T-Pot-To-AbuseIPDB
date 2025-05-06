exports.MAIN = {
	// Server
	COWRIE_LOG_FILE: '~/tpotce/data/cowrie/log/cowrie.json',
	DIONAEA_LOG_FILE: '~/tpotce/data/dionaea/log/dionaea.json',
	HONEYTRAP_LOG_FILE: '~/tpotce/data/honeytrap/log/attackers.json',
	CACHE_FILE: './tmp/tpot-abuseipdb-reporter.cache',
	SERVER_ID: null,
	EXTENDED_LOGS: false,

	// Network
	IP_REFRESH_SCHEDULE: '0 */6 * * *', // CRON: How often the script should check the IP address assigned by the ISP to prevent accidental self-reporting. If you have a static IP, you can set it to '0 0 1 * *' (once a month). Default: every 6 hours
	IPv6_SUPPORT: true, // Specifies whether the device has an assigned IPv6 address.

	// Reporting
	ABUSEIPDB_API_KEY: '', // Secret API key for AbuseIPDB.
	IP_REPORT_COOLDOWN: 12 * 60 * 60 * 1000, // Minimum time (12 hours in this example) that must pass before the same IP address can be reported again. Do not set values like 1 hour, as it wouldn't make sense due to rate limits.

	// Automatic Updates
	AUTO_UPDATE_ENABLED: false, // Should the script automatically update to the latest version using 'git pull'? If enabled, monitor the script periodically — incompatibilities may occasionally occur with the config file.
	AUTO_UPDATE_SCHEDULE: '0 18 * * *', // CRON: Schedule for automatic script updates. Default: every day at 18:00

	// Discord Webhooks
	DISCORD_WEBHOOKS_ENABLED: false, // Should the script send webhooks? These will include error reports, daily summaries, and other related information.
	DISCORD_WEBHOOKS_URL: '',
	DISCORD_WEBHOOK_USERNAME: 'SERVER_ID', // The name displayed as the message author on Discord. If you don't want to set it, leave the value as null. Providing SERVER_ID as a string will display this.MAIN.SERVER_ID.
};
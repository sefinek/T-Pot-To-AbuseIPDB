exports.MAIN = {
	// My Server
	DIONAEA_LOG_FILE: '~/tpotce/data/dionaea/log/dionaea.json',
	HONEYTRAP_LOG_FILE: '~/tpotce/data/honeytrap/log/attackers.json',
	COWRIE_LOG_FILE: '~/tpotce/data/cowrie/log/cowrie.json',
	CACHE_FILE: '/tmp/tpot-abuseipdb-reporter.cache',
	SERVER_ID: null, // The server name that will be visible in the reports (e.g., 'homeserver1'). If you don't want to define it, leave the value as null.
	IP_REFRESH_SCHEDULE: '0 */6 * * *', // CRON: How often should the script check the IP address assigned by the ISP to prevent accidental self-reporting? Default: every 6 hours
	IPv6_SUPPORT: true, // Specifies whether the device has been assigned an IPv6 address.

	// Reporting
	ABUSEIPDB_API_KEY: '', // Secret API key for AbuseIPDB.
	IP_REPORT_COOLDOWN: 12 * 60 * 60 * 1000, // The minimum time (12 hours) that must pass before reporting the same IP address again.

	// Automatic Updates
	AUTO_UPDATE_ENABLED: true, // Do you want the script to automatically update to the latest version using 'git pull'? (true = enabled, false = disabled)
	AUTO_UPDATE_SCHEDULE: '0 5 * * *', // CRON: Schedule for automatic script updates. Default: every day at 05:00

	// Discord Webhooks
	DISCORD_WEBHOOKS_ENABLED: false, // Should the script send webhooks? They will contain error reports, daily summaries related to reports, etc.
	DISCORD_WEBHOOKS_URL: '', // Webhook URL.
};
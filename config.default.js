exports.MAIN = {
	/* --------------------------- Server --------------------------- */
	SERVER_ID: null, // Server identifier (e.g., 'pl-waw-honeypot', 'home-honeypot', 'isp-orange-de'). Use 'development' for testing only. 'production' has no special effect. Use null to leave it unset.
	EXTENDED_LOGS: false, // Specifies whether the script outputs additional information to the logs.
	COWRIE_LOG_FILE: '~/tpotce/data/cowrie/log/cowrie.json',
	DIONAEA_LOG_FILE: '~/tpotce/data/dionaea/log/dionaea.json',
	HONEYTRAP_LOG_FILE: '~/tpotce/data/honeytrap/log/attackers.json',
	CACHE_FILE: './tmp/tpot-abuseipdb-reporter.cache',

	/* --------------------------- History --------------------------- */
	LOG_IP_HISTORY_ENABLED: false, // Stores the collected data in .txt files inside separate subfolders named after IP addresses.
	LOG_IP_HISTORY_DIR: './data', // Where should the collected data be saved? This folder will store subfolders named after IP addresses.

	/* --------------------------- Network --------------------------- */
	IP_ASSIGNMENT: 'dynamic', // IP assignment type: 'static' for a fixed IP, 'dynamic' if it may change over time.
	IP_REFRESH_SCHEDULE: '0 */6 * * *', // Cron schedule for checking the public IP assigned by your ISP. Used only with dynamic IPs to prevent accidental self-reporting. If IP_ASSIGNMENT is set to 'static', the IP is checked only once.
	IPv6_SUPPORT: true, // IPv6 support: true if the device has a globally routable address assigned by the ISP.

	/* --------------------------- Reports --------------------------- */
	ABUSEIPDB_API_KEY: '', // https://www.abuseipdb.com/account/api
	IP_REPORT_COOLDOWN: 6 * 60 * 60 * 1000, // Minimum time between reports of the same IP. Must be >= 15 minutes. Do not set values like 1 hour, as it would not make sense due to rate limits.

	/* --------------------------- Automatic Updates --------------------------- */
	AUTO_UPDATE_ENABLED: false, // Set to true to enable automatic updates via "git pull", false to disable. This option is discouraged due to potential future incompatibilities. Enable it only if you actively monitor the server and want the latest version.
	AUTO_UPDATE_SCHEDULE: '0 14,16,20 * * *', // Cron schedule for automatic updates. Default: every day at 14:00, 16:00, 20:00

	/* --------------------------- Discord Webhooks --------------------------- */
	DISCORD_WEBHOOK_ENABLED: false, // Enables sending Discord webhooks with error reports, execution status, and other events.
	DISCORD_WEBHOOK_URL: '',
	DISCORD_WEBHOOK_USERNAME: 'SERVER_ID', // Username shown as the message author. Use null for default. 'SERVER_ID' resolves to this.MAIN.SERVER_ID.
	DISCORD_USER_ID: '', // Your Discord account identifier.
};
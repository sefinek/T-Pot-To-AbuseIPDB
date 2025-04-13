const { dirname } = require('node:path');
const { mkdirSync, existsSync, readFileSync, writeFileSync } = require('node:fs');
const { CACHE_FILE, IP_REPORT_COOLDOWN } = require('../config.js').MAIN;
const log = require('../utils/log.js');

const reportedIPs = new Map();

const ensureCacheDir = () => {
	const dir = dirname(CACHE_FILE);
	if (!existsSync(dir)) {
		mkdirSync(dir, { recursive: true });
		log(0, `Created missing directory for cache: ${dir}`);
	}
};

const loadReportedIPs = () => {
	ensureCacheDir();

	if (existsSync(CACHE_FILE)) {
		readFileSync(CACHE_FILE, 'utf8')
			.split('\n')
			.filter(Boolean)
			.forEach(line => {
				const [ip, time] = line.trim().split(/\s+/);
				if (ip && !isNaN(time)) reportedIPs.set(ip, Number(time));
			});

		log(0, `📃 Loaded ${reportedIPs.size} IPs from ${CACHE_FILE}`);
	} else {
		log(0, `📃 ${CACHE_FILE} does not exist. No data to load.`);
	}
};

const saveReportedIPs = () => {
	ensureCacheDir();
	writeFileSync(CACHE_FILE, Array.from(reportedIPs).map(([ip, time]) => `${ip} ${time}`).join('\n'), 'utf8');
};

const isIPReportedRecently = ip => {
	const reportedTime = reportedIPs.get(ip);
	return reportedTime && (Date.now() / 1000 - reportedTime < IP_REPORT_COOLDOWN / 1000);
};

const markIPAsReported = ip => reportedIPs.set(ip, Math.floor(Date.now() / 1000));

module.exports = { reportedIPs, loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported };
const fs = require('node:fs');
const path = require('node:path');
const chokidar = require('chokidar');
const readline = require('node:readline');
const log = require('../utils/log.js');
const { DIONAEA_LOG_FILE, SERVER_ID } = require('../config.js').MAIN;

const LOG_FILE = path.resolve(DIONAEA_LOG_FILE);
let fileOffset = 0;

const getReportDetails = (entry, dpt) => {
	const protocol = entry?.connection?.protocol || 'unknown';
	const timestamp = entry?.timestamp || new Date().toISOString();

	let category, comment;
	switch (protocol) {
	case 'mssqld': {
		const username = entry?.credentials?.username?.[0];
		const password = entry?.credentials?.password?.[0];

		category = '18'; // Brute-Force
		if (username && !password) {
			comment = `Honeypot [${SERVER_ID}]: MSSQL brute-force with username '${username}' and empty password`;
		} else if (username && password) {
			comment = `Honeypot [${SERVER_ID}]: MSSQL brute-force with credentials '${username}:${password}'`;
		} else {
			comment = `Honeypot [${SERVER_ID}]: MSSQL connection attempt without credentials`;
		}
		break;
	}
	case 'httpd':
		category = '14,21'; // Web App Attack
		comment = `Honeypot [${SERVER_ID}]: HTTP connection on port ${dpt}, potential web application scan`;
		break;
	case 'ftp':
		category = '5'; // FTP Brute-Force
		comment = `Honeypot [${SERVER_ID}]: FTP brute-force attempt on port ${dpt}`;
		break;
	case 'smbd':
		category = '21'; // Web App Attack
		comment = `Honeypot [${SERVER_ID}]: SMB access attempt or enumeration on port ${dpt}`;
		break;
	case 'mysql':
		category = '18'; // Brute-Force
		comment = `Honeypot [${SERVER_ID}]: MySQL brute-force login attempt on port ${dpt}`;
		break;
	case 'tftp':
		category = '20'; // Exploited Host
		comment = `Honeypot [${SERVER_ID}]: TFTP access, possibly malicious file transfer on port ${dpt}`;
		break;
	case 'upnp':
		category = '14'; // Port Scan
		comment = `Honeypot [${SERVER_ID}]: UPnP device scan or enumeration attempt on port ${dpt}`;
		break;
	case 'mqtt':
		category = '14,23'; // Port Scan, IoT Targeted
		comment = `Honeypot [${SERVER_ID}]: MQTT connection attempt, likely targeting IoT device on port ${dpt}`;
		break;
	default: {
		category = '14,15'; // Port Scan, Possible Exploit
		comment = `Honeypot [${SERVER_ID}]: MQTT connection attempt, likely targeting IoT device on port ${dpt}`;
	}
	}

	return { service: protocol.toUpperCase(), comment, category, timestamp };
};

module.exports = report => {
	if (!fs.existsSync(LOG_FILE)) {
		log(2, `DIONAEA -> Log file not found: ${LOG_FILE}`);
		return;
	}

	fileOffset = fs.statSync(LOG_FILE).size;

	chokidar.watch(LOG_FILE, { persistent: true, ignoreInitial: true }).on('change', file => {
		const stats = fs.statSync(file);
		if (stats.size < fileOffset) {
			fileOffset = 0;
			log(0, 'DIONAEA -> Log truncated, offset reset');
		}

		const rl = readline.createInterface({
			input: fs.createReadStream(file, { start: fileOffset, encoding: 'utf8' }),
		});

		rl.on('line', async line => {
			try {
				const entry = JSON.parse(line);
				const srcIp = entry?.src_ip;
				const dpt = entry?.dst_port;
				if (!srcIp || !dpt) return;

				const { service, timestamp, category, comment } = getReportDetails(entry, dpt);
				await report('DIONAEA', { srcIp, dpt, service, timestamp }, category, comment);
			} catch (err) {
				log(2, `DIONAEA -> Invalid JSON in the log: ${err.message}`);
			}
		});

		rl.on('close', () => fileOffset = stats.size);
	});

	log(0, '🛡️ DIONAEA -> Watcher initialized');
};
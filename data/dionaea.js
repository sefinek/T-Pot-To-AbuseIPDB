const fs = require('node:fs');
const path = require('node:path');
const chokidar = require('chokidar');
const { createInterface } = require('node:readline');
const log = require('../utils/log.js');
const { DIONAEA_LOG_FILE, SERVER_ID } = require('../config.js').MAIN;

const LOG_FILE = path.resolve(DIONAEA_LOG_FILE);
let fileOffset = 0;

const getReportDetails = (entry, dpt) => {
	const proto = entry?.connection?.protocol || 'unknown';
	const timestamp = entry?.timestamp || new Date().toISOString();

	const categories = [];
	let comment;
	switch (proto) {
	case 'mssqld': {
		const username = entry?.credentials?.username?.[0];
		const password = entry?.credentials?.password?.[0];
		if (username && !password) {
			categories.push('18');
			comment = `Honeypot [${SERVER_ID}]: MSSQL traffic (on port ${dpt}) with username \`${username}\` and empty password`;
		} else if (username && password) {
			categories.push('18');
			comment = `Honeypot [${SERVER_ID}]: MSSQL traffic (on port ${dpt}) with credentials \`${username}:${password}\``;
		} else {
			comment = `Honeypot [${SERVER_ID}]: MSSQL traffic (on port ${dpt}) without login credentials`;
			categories.push('14');
		}
		break;
	}
	case 'httpd':
		categories.push('21');
		comment = `Honeypot [${SERVER_ID}]: Incoming HTTP traffic on ${dpt}`;
		break;
	case 'ftp':
		categories.push('5', '18');
		comment = `Honeypot [${SERVER_ID}]: FTP traffic detected on ${dpt}`;
		break;
	case 'smbd':
		categories.push('14');
		comment = `Honeypot [${SERVER_ID}]: SMB traffic observed on ${dpt}`;
		break;
	case 'mysql':
		categories.push('18', '14');
		comment = `Honeypot [${SERVER_ID}]: MySQL-related traffic detected on ${dpt}`;
		break;
	case 'tftp':
		categories.push('20');
		comment = `Honeypot [${SERVER_ID}]: TFTP protocol traffic on ${dpt}`;
		break;
	case 'upnp':
		categories.push('23');
		comment = `Honeypot [${SERVER_ID}]: UPnP traffic detected on ${dpt}`;
		break;
	case 'mqtt':
		categories.push('23');
		comment = `Honeypot [${SERVER_ID}]: MQTT protocol traffic on ${dpt}`;
		break;
	default: {
		categories.push('14');
		comment = `Honeypot [${SERVER_ID}]: Unauthorized traffic on ${dpt}/${proto}`;
	}
	}

	return { service: proto.toUpperCase(), comment, categories, timestamp };
};

module.exports = (report, abuseIPDBRateLimited) => {
	if (abuseIPDBRateLimited) return;
	if (!fs.existsSync(LOG_FILE)) {
		log(2, `DIONAEA -> Log file not found: ${LOG_FILE}`);
		return;
	}

	fileOffset = fs.statSync(LOG_FILE).size;

	chokidar.watch(LOG_FILE, {
		persistent: true,
		ignoreInitial: true,
		awaitWriteFinish: { stabilityThreshold: 300, pollInterval: 100 },
		alwaysStat: true,
		atomic: true,
	}).on('change', file => {
		const stats = fs.statSync(file);
		if (stats.size < fileOffset) {
			fileOffset = 0;
			return log(0, 'DIONAEA -> Log truncated, offset reset');
		}

		const rl = createInterface({ input: fs.createReadStream(file, { start: fileOffset, encoding: 'utf8' }) });
		rl.on('line', async line => {
			let entry;
			try {
				entry = JSON.parse(line);
			} catch (err) {
				log(2, `COWRIE -> JSON parse error: ${err.message}`);
				log(2, `COWRIE -> Faulty line: ${JSON.stringify(line)}`);
				return;
			}

			try {
				const srcIp = entry?.src_ip;
				const dpt = entry?.dst_port;
				if (!srcIp || !dpt) return;

				const { service, timestamp, categories, comment } = getReportDetails(entry, dpt);
				await report('DIONAEA', { srcIp, dpt, service, timestamp }, categories, comment);
			} catch (err) {
				log(2, err);
			}
		});

		rl.on('close', () => fileOffset = stats.size);
	});

	log(0, '🛡️ DIONAEA -> Watcher initialized');
};
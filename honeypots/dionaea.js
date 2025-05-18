const fs = require('node:fs');
const path = require('node:path');
const chokidar = require('chokidar');
const { createInterface } = require('node:readline');
const logger = require('../scripts/logger.js');
const { DIONAEA_LOG_FILE, SERVER_ID } = require('../config.js').MAIN;

const LOG_FILE = path.resolve(DIONAEA_LOG_FILE);
let fileOffset = 0;

const getReportDetails = (entry, dpt) => {
	const proto = entry?.connection?.protocol || 'unknown';
	const timestamp = entry?.timestamp || new Date().toISOString();

	let categories, comment;
	switch (proto) {
	case 'mssqld': {
		const username = entry?.credentials?.username?.[0];
		const password = entry?.credentials?.password?.[0];
		if (username && !password) {
			categories = '18';
			comment = `MSSQL traffic (on ${dpt}) with username ${username} and empty password`;
		} else if (username && password) {
			categories = '18';
			comment = `MSSQL traffic (on ${dpt}) with credentials ${username}:${password}`;
		} else {
			categories = '14';
			comment = `MSSQL traffic (on ${dpt}) without login credentials`;
		}
		break;
	}
	case 'httpd':
		categories = '21,19';
		comment = `Incoming HTTP traffic on port ${dpt}`;
		break;
	case 'ftp':
		categories = '5,18';
		comment = `FTP brute-force or probing on port ${dpt}`;
		break;
	case 'smbd':
		categories = '23';
		comment = `SMB traffic on port ${dpt}`;
		break;
	case 'mysql':
		categories = '18';
		comment = `MySQL brute-force or probing on port ${dpt}`;
		break;
	case 'tftp':
		categories = '20';
		comment = `TFTP protocol traffic on ${dpt}`;
		break;
	case 'upnp': case 'mqtt':
		categories = '23';
		comment = `Unauthorized ${proto.toUpperCase()} traffic on ${dpt}`;
		break;
	default:
		categories = '14';
		comment = `Unauthorized traffic on ${dpt}/${proto}`;
	}

	return { proto: proto.toUpperCase(), comment: `Honeypot ${SERVER_ID ? `[${SERVER_ID}]` : 'hit'}: ${comment}`, categories, timestamp };
};

module.exports = reportIp => {
	if (!fs.existsSync(LOG_FILE)) {
		logger.log(`DIONAEA -> Log file not found: ${LOG_FILE}`, 3, true);
		return;
	}

	fileOffset = fs.statSync(LOG_FILE).size;

	chokidar.watch(LOG_FILE, {
		persistent: true,
		ignoreInitial: true,
		awaitWriteFinish: { stabilityThreshold: 1000, pollInterval: 300 },
		alwaysStat: true,
		atomic: true,
	}).on('change', file => {
		const stats = fs.statSync(file);
		if (stats.size < fileOffset) {
			fileOffset = 0;
			return logger.log('DIONAEA -> Log truncated, offset reset', 2, true);
		}

		const rl = createInterface({ input: fs.createReadStream(file, { start: fileOffset, encoding: 'utf8' }) });
		rl.on('line', async line => {
			let entry;
			try {
				entry = JSON.parse(line);
			} catch (err) {
				logger.log(`DIONAEA -> JSON parse error: ${err.message}\nFaulty line: ${JSON.stringify(line)}`, 3, true);
				return;
			}

			try {
				const srcIp = entry?.src_ip;
				const dpt = entry?.dst_port;
				if (!srcIp || !dpt) return;

				const { proto, timestamp, categories, comment } = getReportDetails(entry, dpt);
				await reportIp('DIONAEA', { srcIp, dpt, proto, timestamp }, categories, comment);
			} catch (err) {
				logger.log(err, 3);
			}
		});

		rl.on('close', () => fileOffset = stats.size);
	});

	logger.log('🛡️ DIONAEA » Watcher initialized', 1);
};
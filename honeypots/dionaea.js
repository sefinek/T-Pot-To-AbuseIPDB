const fs = require('node:fs');
const path = require('node:path');
const TailFile = require('@logdna/tail-file');
const split2 = require('split2');
const logger = require('../scripts/logger.js');
const { DIONAEA_LOG_FILE, SERVER_ID } = require('../config.js').MAIN;

const LOG_FILE = path.resolve(DIONAEA_LOG_FILE);

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
		return logger.log(`DIONAEA -> Log file not found: ${LOG_FILE}`, 3, true);
	}

	const tail = new TailFile(LOG_FILE);
	tail
		.on('tail_error', err => logger.log(err, 3))
		.start()
		.catch(err => logger.log(err, 3));

	tail
		.pipe(split2())
		.on('data', async line => {
			if (!line.length) return;

			let entry;
			try {
				entry = JSON.parse(line);
			} catch (err) {
				return logger.log(`DIONAEA -> JSON parse error: ${err.message}\nFaulty line: ${JSON.stringify(line)}`, 3, true);
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

	logger.log('🛡️ DIONAEA » Watcher initialized', 1);
	return { tail, flush: async () => {} };
};
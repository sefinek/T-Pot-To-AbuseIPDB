const fs = require('node:fs');
const path = require('node:path');
const chokidar = require('chokidar');
const readline = require('node:readline');
const log = require('../utils/log.js');
const { HONEYTRAP_LOG_FILE, SERVER_ID } = require('../config.js').MAIN;

const LOG_FILE = path.resolve(HONEYTRAP_LOG_FILE);
let fileOffset = 0;

const HEADER_PRIORITY = ['user-agent', 'accept', 'accept-language', 'accept-encoding'];
const capitalizeHeader = header => header.split('-').map(word => word[0].toUpperCase() + word.slice(1)).join('-');

const parseHttpRequest = (hex, port) => {
	const raw = Buffer.from(hex, 'hex').toString('utf8');
	const lines = raw.replace(/\r\n|\r/g, '\n').trim().split('\n');

	const requestLineRaw = lines.shift()?.trim() || '';
	const protocol = requestLineRaw.match(/HTTP\/[0-9.]+/i)?.[0]?.toUpperCase() || 'HTTP';
	const requestLine = requestLineRaw.replace(/\s*HTTP\/[0-9.]+$/i, '');

	const headers = {};
	const body = [];
	let parsingBody = false;

	for (const line of lines) {
		if (parsingBody) {
			body.push(line);
			continue;
		}
		if (!line.trim()) {
			parsingBody = true;
			continue;
		}
		const [key, ...value] = line.split(':');
		if (value.length && key.toLowerCase() !== 'host') {
			headers[key.trim().toLowerCase()] = value.join(':').trim();
		}
	}

	const formattedHeaders = HEADER_PRIORITY
		.filter(h => headers[h])
		.map(h => `${capitalizeHeader(h)}: ${headers[h]}`)
		.join('\n');

	let output = `Honeypot [${SERVER_ID}]: ${protocol} request on ${port}\n\n${requestLine}`;
	if (formattedHeaders) output += `\n${formattedHeaders}`;

	if (requestLineRaw.startsWith('POST')) {
		const bodyContent = body.join('\n').trim();
		if (bodyContent) output += `\nPOST Data: ${bodyContent}`;
	}

	return output;
};

const getReportDetails = entry => {
	const attack = entry?.attack_connection;
	const port = attack?.local_port;
	const proto = (attack?.protocol || 'unknown').toUpperCase();
	const hex = attack?.payload?.data_hex || '';
	const ascii = Buffer.from(hex, 'hex').toString('utf8').replace(/\s+/g, ' ').toLowerCase();
	const payloadLen = attack?.payload?.length || 0;

	let category, comment;
	switch (true) {
	case payloadLen === 0:
		category = '14'; // Port Scan
		comment = `Honeypot [${SERVER_ID}]: Empty payload on port ${port} (likely service probe)`;
		break;

	case (/^1603/).test(hex):
		category = '14'; // TLS handshake
		comment = `Honeypot [${SERVER_ID}]: TLS handshake on port ${port} (likely service probe)`;
		break;

	case (/HTTP\/(0\.9|1\.0|1\.1|2|3)/i).test(ascii): // HTTP/Version
		category = '21';
		comment = parseHttpRequest(hex, port);
		break;

	case port === 11211: case ascii.includes('stats'):
		category = '14';
		comment = `Honeypot [${SERVER_ID}]: Memcached command on port ${port}`;
		break;

	case ascii.includes('ssh'):
		category = '14,18';
		comment = `Honeypot [${SERVER_ID}]: SSH handshake/banner on port ${port}`;
		break;

	case ascii.includes('mgmt'):
		category = '14,23';
		comment = `Honeypot [${SERVER_ID}]: MGMT/IoT-specific traffic on port ${port}`;
		break;

	case (/(admin|root|wget|curl|nc|bash|cmd|eval|php|sh|bin)/).test(ascii):
		category = '15';
		comment = `Honeypot [${SERVER_ID}]: Suspicious payload on port ${port} — possible command injection`;
		break;

	case payloadLen > 1000:
		category = '14,15';
		comment = `Honeypot [${SERVER_ID}]: Large payload (${payloadLen} bytes) on port ${port}`;
		break;

	default:
		category = '14,15'; // Port Scan, Possible Exploit
		comment = `Honeypot [${SERVER_ID}]: Unclassified ${proto} traffic on port ${port}`;
		break;
	}

	return {
		service: proto,
		comment,
		category,
		timestamp: entry?.['@timestamp'],
	};
};

module.exports = report => {
	if (!fs.existsSync(LOG_FILE)) {
		log(2, `HONEYTRAP -> Log file not found: ${LOG_FILE}`);
		return;
	}

	fileOffset = fs.statSync(LOG_FILE).size;

	chokidar.watch(LOG_FILE, { persistent: true, ignoreInitial: true }).on('change', file => {
		const stats = fs.statSync(file);
		if (stats.size < fileOffset) {
			fileOffset = 0;
			log(0, 'HONEYTRAP -> Log truncated, offset reset');
		}

		const rl = readline.createInterface({
			input: fs.createReadStream(file, { start: fileOffset, encoding: 'utf8' }),
		});

		rl.on('line', async line => {
			try {
				const entry = JSON.parse(line);
				const srcIp = entry?.attack_connection?.remote_ip;
				const dpt = entry?.attack_connection?.local_port;
				if (!srcIp || !dpt) return;

				const { service, timestamp, category, comment } = getReportDetails(entry);
				await report('HONEYTRAP', { srcIp, dpt, service, timestamp }, category, comment);
			} catch (err) {
				log(2, `HONEYTRAP -> Invalid JSON in log: ${err.message}`);
			}
		});

		rl.on('close', () => {
			fileOffset = stats.size;
		});
	});

	log(0, '🛡️ HONEYTRAP -> Watcher initialized');
};
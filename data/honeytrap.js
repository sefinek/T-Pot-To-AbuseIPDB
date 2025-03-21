const fs = require('node:fs');
const path = require('node:path');
const chokidar = require('chokidar');
const readline = require('node:readline');
const log = require('../utils/log.js');
const { HONEYTRAP_LOG_FILE, SERVER_ID } = require('../config.js').MAIN;

const LOG_FILE = path.resolve(HONEYTRAP_LOG_FILE);
let fileOffset = 0;

const headerOrder = ['user-agent', 'accept', 'accept-language', 'accept-encoding'];
const capitalizeHeader = h => h.split('-').map(part => part.charAt(0).toUpperCase() + part.slice(1)).join('-');

const parseHttpRequest = (hex, port) => {
	const raw = Buffer.from(hex, 'hex').toString('utf8');
	const lines = raw.replace(/\r\n|\r/g, '\n').trim().split('\n');

	const requestLineRaw = lines.shift()?.trim() || '';
	const proto = requestLineRaw.match(/HTTP\/[0-9.]+/i)?.[0]?.toUpperCase() || 'HTTP';
	const requestLine = requestLineRaw.replace(/\s*HTTP\/[0-9.]+$/i, '');

	const headers = {};
	const body = [];

	let inBody = false;
	for (const line of lines) {
		if (inBody) {
			body.push(line);
			continue;
		}
		if (!line.trim()) {
			inBody = true;
			continue;
		}
		const [k, ...v] = line.split(':');
		if (v.length) {
			const key = k.trim().toLowerCase();
			if (key !== 'host') headers[key] = v.join(':').trim();
		}
	}

	const shownHeaders = headerOrder
		.filter(h => headers[h])
		.map(h => `${capitalizeHeader(h)}: ${headers[h]}`)
		.join('\n');

	let out = `Honeypot [${SERVER_ID}]: ${proto} request on ${port}\n\n${requestLine}`;
	if (shownHeaders) out += `\n${shownHeaders}`;
	if (requestLineRaw.startsWith('POST')) {
		const bodyContent = body.join('\n').trim();
		if (bodyContent) out += `\nPOST Data: ${bodyContent}`;
	}
	return out;
};

const getReportDetails = entry => {
	const attack = entry?.attack_connection;
	const port = attack?.local_port;
	const proto = (attack?.protocol || 'unknown').toUpperCase();
	const payload = attack?.payload;
	const payloadLen = payload?.length || 0;
	const hex = payload?.data_hex || '';
	const ascii = Buffer.from(hex, 'hex').toString('utf8').replace(/\s+/g, ' ').toLowerCase();

	let category, comment;
	switch (true) {
	case payloadLen === 0:
		category = '14'; // Port Scan
		comment = `Honeypot [${SERVER_ID}]: Empty payload on port ${port} (likely service probe)`;
		break;

	case (/^1603/i).test(hex):
		category = '14'; // TLS handshake = likely probe
		comment = `Honeypot [${SERVER_ID}]: TLS handshake on port ${port} (likely service probe)`;
		break;

	case (/^(474554|504f5354|48545450)/i).test(hex):
		category = '21';
		comment = parseHttpRequest(hex, port);
		break;

	case port === 11211 || ascii.includes('stats'):
		category = '14'; // Memcached scan/probe
		comment = `Honeypot [${SERVER_ID}]: Memcached command on port ${port}`;
		break;

	case (/^(535348)/i).test(hex) || ascii.includes('ssh'):
		category = '14,18'; // Port Scan, Brute-Force
		comment = `Honeypot [${SERVER_ID}]: SSH handshake/banner on port ${port}`;
		break;

	case (/^(4d47534e)/i).test(hex) || ascii.includes('mgmt'):
		category = '14,23'; // Port Scan, IoT Targeted
		comment = `Honeypot [${SERVER_ID}]: MGMT/IoT-specific traffic on port ${port}`;
		break;

	case ascii.match(/(admin|root|wget|curl|nc|bash|cmd|eval|php|sh|bin)/):
		category = '15'; // Possible Exploit
		comment = `Honeypot [${SERVER_ID}]: Suspicious payload on port ${port} — possible command injection`;
		break;

	case payloadLen > 1000:
		category = '14,15'; // Port Scan, Hacking / fuzzing
		comment = `Honeypot [${SERVER_ID}]: Large payload (${payloadLen} bytes) on port ${port}`;
		break;

	default:
		category = '14,15'; // Port Scan, Possible Exploit
		comment = `Honeypot [${SERVER_ID}]: Unclassified ${proto} traffic on port ${port}`;
		break;
	}

	return {
		service: proto,
		comment: comment,
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

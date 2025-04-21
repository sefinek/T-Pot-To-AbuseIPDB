const fs = require('node:fs');
const path = require('node:path');
const chokidar = require('chokidar');
const { createInterface } = require('node:readline');
const ipSanitizer = require('../utils/ipSanitizer.js');
const log = require('../utils/log.js');
const { HONEYTRAP_LOG_FILE, SERVER_ID } = require('../config.js').MAIN;

const LOG_FILE = path.resolve(HONEYTRAP_LOG_FILE);
let fileOffset = 0;
let lastFlushTime = Date.now();

const attackBuffer = new Map();

const HEADER_PRIORITY = ['user-agent', 'accept', 'accept-language', 'accept-encoding'];
const capitalizeHeader = header => header.split('-').map(w => w[0].toUpperCase() + w.slice(1)).join('-');

const parseHttpRequest = (hex, dpt) => {
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
		if (value.length && key.toLowerCase() !== 'host') headers[key.trim().toLowerCase()] = value.join(':').trim();
	}

	const formattedHeaders = HEADER_PRIORITY
		.filter(h => headers[h])
		.map(h => `${capitalizeHeader(h)}: ${headers[h]}`)
		.join('\n');

	let output = `${protocol} request on ${dpt}\n\n${requestLine}`;
	if (formattedHeaders) output += `\n${formattedHeaders}`;

	if (requestLineRaw.startsWith('POST')) {
		const bodyContent = body.join('\n').trim();
		if (bodyContent) output += `\nPOST Data: ${ipSanitizer(bodyContent)}`;
	}

	return output;
};

const getReportDetails = (entry, dpt) => {
	const proto = entry?.attack_connection?.protocol || 'unknown';
	const hex = entry?.attack_connection?.payload?.data_hex || '';
	const ascii = Buffer.from(hex, 'hex').toString('utf8').replace(/\s+/g, ' ').toLowerCase();
	const payloadLen = entry?.attack_connection?.payload?.length || 0;

	let categories, comment;
	switch (true) {
	case payloadLen === 0:
		categories = '14';
		comment = `Empty payload on ${dpt}/${proto} (likely service probe)`;
		break;

	case payloadLen > 1000:
		categories = '15';
		comment = `Large payload (${payloadLen} bytes) on ${dpt}/${proto}`;
		break;

	case (/HTTP\/(0\.9|1\.0|1\.1|2|3)/i).test(ascii):
		categories = '21';
		comment = parseHttpRequest(hex, dpt);
		break;

	case ascii.includes('ssh'):
		categories = '18,22';
		comment = `SSH handshake/banner on ${dpt}/${proto} (${payloadLen} bytes of payload)`;
		break;

	case ascii.includes('cookie:'):
		categories = '21,15';
		comment = `HTTP header with cookie on ${dpt}/${proto}`;
		break;

	case (/(admin|root|wget|curl|bash|eval|php|bin)/).test(ascii):
		categories = '15';
		comment = `Suspicious payload on ${dpt}/${proto} (possible command injection)`;
		break;

	default:
		categories = '14';
		comment = `Unauthorized traffic on ${dpt}/${proto} (${payloadLen} bytes of payload)`;
		break;
	}

	return { service: proto, comment: `Honeypot ${SERVER_ID ? `[${SERVER_ID}]` : 'hit'}: ${comment}`, categories, timestamp: entry?.['@timestamp'] };
};

const flushReport = async reportIp => {
	if (!attackBuffer.size) return;

	for (const [, ports] of attackBuffer.entries()) {
		const sortedPorts = Array.from(ports.entries())
			.sort(([, a], [, b]) => b.count - a.count)
			.slice(0, 6);

		for (const [port, data] of sortedPorts) {
			await reportIp('HONEYTRAP', { port, count: data.count, service: data.service, timestamp: data.timestamp }, data.categories, data.comment);
		}
	}

	log(0, `HONEYTRAP -> Flushed ${attackBuffer.size} IPs`);
	attackBuffer.clear();
};

module.exports = reportIp => {
	if (!fs.existsSync(LOG_FILE)) {
		log(2, `HONEYTRAP -> Log file not found: ${LOG_FILE}`, 1);
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
			return log(0, 'HONEYTRAP -> Log truncated, offset reset', 1);
		}

		const rl = createInterface({ input: fs.createReadStream(file, { start: fileOffset, encoding: 'utf8' }) });
		rl.on('line', async line => {
			let entry;
			try {
				entry = JSON.parse(line);
			} catch (err) {
				log(2, `HONEYTRAP -> JSON parse error: ${err.message}`, 1);
				log(2, `HONEYTRAP -> Faulty line: ${JSON.stringify(line)}`);
				return;
			}

			try {
				const srcIp = entry?.attack_connection?.remote_ip;
				const dpt = entry?.attack_connection?.local_port;
				if (!srcIp || !dpt) return;

				const { service, timestamp, categories, comment } = getReportDetails(entry, dpt);
				let ipData = attackBuffer.get(srcIp);
				if (!ipData) {
					ipData = new Map();
					attackBuffer.set(srcIp, ipData);
				}

				let portData = ipData.get(dpt);
				if (portData) {
					portData.count++;
				} else {
					portData = { count: 1, service, timestamp, categories, comment };
					ipData.set(dpt, portData);
				}

				log(0, `HONEYTRAP -> ${srcIp} on ${dpt} | attempts: ${portData.count}`);
			} catch (err) {
				log(2, err);
			}
		});

		rl.on('close', () => fileOffset = stats.size);
	});

	setInterval(async () => {
		if (Date.now() >= lastFlushTime + 15 * 60 * 1000) {
			await flushReport(reportIp);
			lastFlushTime = Date.now();
		}
	}, 60 * 1000);

	log(0, '🛡️ HONEYTRAP -> Watcher initialized');
};
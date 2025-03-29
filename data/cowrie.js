const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const chokidar = require('chokidar');
const { createInterface } = require('node:readline');
const log = require('../utils/log.js');
const ipSanitizer = require('../utils/ipSanitizer.js');
const { COWRIE_LOG_FILE, SERVER_ID } = require('../config.js').MAIN;

const LOG_FILE = path.resolve(COWRIE_LOG_FILE);
const REPORT_DELAY = SERVER_ID === 'development' ? 30 * 1000 : 10 * 60 * 1000;

let fileOffset = 0;
const ipBuffers = new Map();

const flushIpBuffer = async (ip, report) => {
	const buffer = ipBuffers.get(ip);
	if (!buffer) return;

	clearTimeout(buffer.timer);
	ipBuffers.delete(ip);

	const allSessions = buffer.sessions;
	if (allSessions.length === 0) return;

	const categories = new Set(['15']);
	const credsSet = new Set();
	const commands = [];
	let port = null;
	let proto = null;
	let sshVersion = null;
	let timestamp = null;
	let suspiciousDownloadHash = null;

	for (const session of allSessions) {
		port = port || session.port;
		proto = proto || session.proto;
		sshVersion = sshVersion || session.sshVersion;
		timestamp = timestamp || session.timestamp;
		session.credentials?.forEach((_, cred) => credsSet.add(cred));
		commands.push(...session.commands);

		if (session.download && session.download.url) {
			const url = session.download.url.toLowerCase();
			if (url.endsWith('.elf') || url.endsWith('.sh') || url.endsWith('.bin') || url.endsWith('.py')) {
				categories.add('21');
				try {
					const filePath = path.resolve(session.download.outfile || '');
					if (fs.existsSync(filePath)) {
						const fileBuf = fs.readFileSync(filePath);
						suspiciousDownloadHash = crypto.createHash('sha256').update(fileBuf).digest('hex');
					}
				} catch {}
			}
		}
	}

	if (!ip || !port || !proto) return log(1, `COWRIE -> Incomplete data for ${ip}, discarded`);

	const creds = [...credsSet];
	const loginAttempts = creds.length;
	const cmdCount = commands.length;
	if (loginAttempts >= 2) categories.add('18');
	if (proto === 'ssh') categories.add('22');
	if (proto === 'telnet') categories.add('23');
	if (cmdCount > 0) categories.add('20');
	if (loginAttempts === 0 && cmdCount === 0) categories.add('14');

	const lines = [];
	lines.push(`Honeypot [${SERVER_ID}]: ${creds.length >= 1 ? 'A brute-force attack' : 'An unauthorized connection attempt'} detected on ${port}/${proto.toUpperCase()}`);
	if (creds.length === 1) {
		lines.push(`• Credential used: ${creds[0]}`);
	} else if (creds.length > 1) {
		lines.push(`• Credentials used: ${creds.join(', ')}`);
	}

	if (loginAttempts >= 1) lines.push(`• Number of login attempts: ${loginAttempts}`);
	if (cmdCount > 0) lines.push(`• ${cmdCount} command(s) were executed during the session`);
	if (sshVersion) lines.push(`• Client: ${sshVersion}`);
	if (suspiciousDownloadHash) lines.push(`• SHA256 of suspicious file: ${suspiciousDownloadHash}`);

	await report('COWRIE', {
		srcIp: ip,
		dpt: port,
		service: proto.toUpperCase(),
		timestamp,
	}, [...categories].join(','), lines.join('\n'));
};

const processCowrieLogLine = async (entry, report) => {
	const ip = entry?.src_ip;
	const sessionId = entry?.session;
	const { eventid } = entry;
	if (!ip || !eventid || !sessionId) return log(1, 'COWRIE -> Skipped: missing src_ip, eventid or sessionId');

	let buffer = ipBuffers.get(ip);
	if (!buffer) {
		buffer = {
			sessions: [],
			timer: setTimeout(() => flushIpBuffer(ip, report), REPORT_DELAY),
			reportPendingLogged: false,
		};
		ipBuffers.set(ip, buffer);
	}

	if (!buffer.reportPendingLogged) buffer.reportPendingLogged = true;

	let session = buffer.sessions.find(s => s.sessionId === sessionId);
	if (!session && eventid !== 'cowrie.session.closed') {
		session = {
			sessionId,
			srcIp: ip,
			port: entry.dst_port,
			proto: entry.protocol,
			timestamp: entry.timestamp,
			credentials: new Map(),
			commands: [],
			sshVersion: null,
			download: null,
		};
		buffer.sessions.push(session);
	}

	if (session) session.timestamp = entry.timestamp;

	switch (eventid) {
	case 'cowrie.session.connect':
		if (session) {
			session.port = entry.dst_port;
			session.proto = entry.protocol;
			log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: Connect`);
		}
		break;

	case 'cowrie.login.success':
	case 'cowrie.login.failed':
		if (session && (entry.username || entry.password)) {
			session.credentials.set(`${ipSanitizer(entry.username)}:${ipSanitizer(entry.password)}`, true);
			const status = eventid === 'cowrie.login.success' ? 'Connected' : 'Failed login';
			log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: ${status} => ${entry.username}:${entry.password}`);
		}
		break;

	case 'cowrie.client.version':
		if (session) {
			session.sshVersion = entry.version;
			log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: SSH version => ${entry.version}`);
		}
		break;

	case 'cowrie.command.input':
		if (session && entry.input) {
			session.commands.push(entry.input);
			log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: $ ${entry.input}`);
		}
		break;

	case 'cowrie.session.file_download':
		if (session && entry.url) {
			session.commands.push(`[file download] ${entry.url}`);
			session.download = { url: entry.url, outfile: entry.outfile };
			log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: File download => ${entry.url}`);
		}
		break;

	case 'cowrie.session.closed':
		log(0, `COWRIE -> ${ip}/${session?.proto}/${session?.port}: Session ${sessionId} closed`);
		break;
	}
};

module.exports = report => {
	if (!fs.existsSync(LOG_FILE)) {
		log(2, `COWRIE -> Log file not found: ${LOG_FILE}`);
		return;
	}

	fileOffset = fs.statSync(LOG_FILE).size;

	chokidar.watch(LOG_FILE, {
		persistent: true,
		ignoreInitial: true,
		awaitWriteFinish: { stabilityThreshold: 500, pollInterval: 100 },
		alwaysStat: true,
		atomic: true,
	}).on('change', file => {
		const stats = fs.statSync(file);
		if (stats.size < fileOffset) {
			fileOffset = 0;
			return log(0, 'COWRIE -> Log truncated, offset reset');
		}

		const rl = createInterface({ input: fs.createReadStream(file, { start: fileOffset, encoding: 'utf8' }) });
		rl.on('line', async line => {
			if (!line.length) return;

			let entry;
			try {
				entry = JSON.parse(line);
			} catch (err) {
				log(2, `COWRIE -> JSON parse error: ${err.message}`);
				log(2, `COWRIE -> Faulty line: ${JSON.stringify(line)}`);
				return;
			}

			try {
				await processCowrieLogLine(entry, report);
			} catch (err) {
				log(2, err);
			}
		});
		rl.on('close', () => fileOffset = stats.size);
	});

	log(0, '🛡️ COWRIE -> Watcher initialized');
};
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const chokidar = require('chokidar');
const { createInterface } = require('node:readline');
const log = require('../scripts/log.js');
const ipSanitizer = require('../scripts/ipSanitizer.js');
const { COWRIE_LOG_FILE, SERVER_ID } = require('../config.js').MAIN;

const LOG_FILE = path.resolve(COWRIE_LOG_FILE);
const REPORT_DELAY = SERVER_ID === 'development' ? 30 * 1000 : 10 * 60 * 1000;

let fileOffset = 0;
const ipBuffers = new Map();

const flushBuffer = async (srcIp, reportIp) => {
	const buffer = ipBuffers.get(srcIp);
	if (!buffer) return;

	clearTimeout(buffer.timer);
	ipBuffers.delete(srcIp);

	const allSessions = buffer.sessions;
	if (allSessions.length === 0) return;

	const categories = new Set(['15']);
	const credsSet = new Set();
	const commands = [];
	let dpt = null, proto = null, sshVersion = null, suspiciousDownloadHash = null, timestamp = null;

	for (const session of allSessions) {
		dpt = dpt || session.dpt;
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

	if (!srcIp || !dpt || !proto) return log(`COWRIE -> Incomplete data for ${srcIp}, discarded`, 2, true);

	const creds = [...credsSet];
	const loginAttempts = creds.length;
	const cmdCount = commands.length;
	if (loginAttempts >= 2) categories.add('18');
	if (proto === 'ssh') categories.add('22');
	if (proto === 'telnet') categories.add('23');
	if (cmdCount > 0) categories.add('20');
	if (loginAttempts === 0 && cmdCount === 0) categories.add('14');

	const lines = [];
	lines.push(`Honeypot ${SERVER_ID ? `[${SERVER_ID}]` : 'hit'}: ${creds.length >= 1 ? 'Brute-force attack' : 'Unauthorized connection attempt'} detected on ${dpt}/${proto.toUpperCase()}`);
	if (creds.length === 1) {
		lines.push(`• Credential used: ${creds[0]}`);
	} else if (creds.length > 1) {
		lines.push(`• Credentials used: ${creds.join(', ')}`);
	}

	if (loginAttempts >= 1) lines.push(`• Number of login attempts: ${loginAttempts}`);
	if (cmdCount > 0) lines.push(`• ${cmdCount} command(s) were executed during the session`);
	if (sshVersion) lines.push(`• Client: ${sshVersion}`);
	if (suspiciousDownloadHash) lines.push(`• SHA256 of suspicious file: ${suspiciousDownloadHash}`);

	const comment = lines.join('\n');
	await reportIp('COWRIE', {
		srcIp,
		dpt,
		service: proto.toUpperCase(),
		timestamp,
	}, [...categories].join(','), comment);

	const [firstLine, ...restLines] = comment.split('\n');
	log(`### ${firstLine}\n${restLines.join('\n')}`, 0, true);
};

const processCowrieLogLine = async (entry, reportIp) => {
	const ip = entry?.src_ip;
	const sessionId = entry?.session;
	const { eventid } = entry;
	if (!ip || !eventid || !sessionId) return log('COWRIE -> Skipped: missing src_ip, eventid or sessionId', 2, true);

	let buffer = ipBuffers.get(ip);
	if (!buffer) {
		buffer = {
			sessions: [],
			timer: setTimeout(() => flushBuffer(ip, reportIp), REPORT_DELAY),
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
			dpt: entry.dst_port,
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
			session.dpt = entry.dst_port;
			session.proto = entry.protocol;
			log(`COWRIE -> ${ip}/${session.proto}/${session.dpt}: Connect`);
		}
		break;

	case 'cowrie.login.success':
	case 'cowrie.login.failed':
		if (session && (entry.username || entry.password)) {
			session.credentials.set(`${ipSanitizer(entry.username)}:${ipSanitizer(entry.password)}`, true);
			const status = eventid === 'cowrie.login.success' ? 'Connected' : 'Failed login';
			log(`COWRIE -> ${ip}/${session.proto}/${session.dpt}: ${status} => ${entry.username}:${entry.password}`);
		}
		break;

	case 'cowrie.client.version':
		if (session) {
			session.sshVersion = entry.version;
			log(`COWRIE -> ${ip}/${session.proto}/${session.dpt}: SSH version => ${entry.version}`);
		}
		break;

	case 'cowrie.command.input':
		if (session && entry.input) {
			session.commands.push(entry.input);
			log(`COWRIE -> ${ip}/${session.proto}/${session.dpt}: $ ${entry.input}`);
		}
		break;

	case 'cowrie.session.file_download':
		if (session && entry.url) {
			session.commands.push(`[file download] ${entry.url}`);
			session.download = { url: entry.url, outfile: entry.outfile };
			log(`COWRIE -> ${ip}/${session.proto}/${session.dpt}: File download => ${entry.url}`);
		}
		break;

	case 'cowrie.session.closed':
		log(`COWRIE -> ${ip}/${session?.proto}/${session?.dpt}: Session ${sessionId} closed`);
		break;
	}
};

module.exports = reportIp => {
	if (!fs.existsSync(LOG_FILE)) {
		log(`COWRIE -> Log file not found: ${LOG_FILE}`, 3, true);
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
			return log('COWRIE -> Log truncated, offset reset', 2, true);
		}

		const rl = createInterface({ input: fs.createReadStream(file, { start: fileOffset, encoding: 'utf8' }) });
		rl.on('line', async line => {
			if (!line.length) return;

			let entry;
			try {
				entry = JSON.parse(line);
			} catch (err) {
				log(`COWRIE -> JSON parse error: ${err.message}`, 3, true);
				log(`COWRIE -> Faulty line: ${JSON.stringify(line)}`, 3, true);
				return;
			}

			try {
				await processCowrieLogLine(entry, reportIp);
			} catch (err) {
				log(err, 3);
			}
		});
		rl.on('close', () => fileOffset = stats.size);
	});

	log('🛡️ COWRIE -> Watcher initialized', 1);
};
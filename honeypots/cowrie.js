const fs = require('node:fs');
const path = require('node:path');
const chokidar = require('chokidar');
const { createInterface } = require('node:readline');
const logger = require('../scripts/logger.js');
const ipSanitizer = require('../scripts/ipSanitizer.js');
const { COWRIE_LOG_FILE, SERVER_ID } = require('../config.js').MAIN;

const LOG_FILE = path.resolve(COWRIE_LOG_FILE);
const REPORT_DELAY = SERVER_ID === 'development' ? 30 * 1000 : 10 * 60 * 1000;

let fileOffset = 0;
const CREDS_LIMIT = 900;
const ipBuffers = new Map();

const extractSessionData = sessions => {
	const credsSet = new Set();
	const commands = [];
	const categories = new Set(['15']);
	const fingerprints = new Set();
	const uploads = [];
	const tunnels = [];
	const kexAlgs = new Set();

	let dpt = null, proto = null, sshVersion = null, timestamp = null;
	let downloadUrl = null;

	for (const s of sessions) {
		dpt ??= s.dpt;
		proto ??= s.proto;
		sshVersion ??= s.sshVersion;
		timestamp ??= s.timestamp;

		s.credentials?.forEach((_, cred) => credsSet.add(cred));
		commands.push(...s.commands);

		if (s.fingerprint) fingerprints.add(s.fingerprint);
		if (s.kexAlgs) s.kexAlgs.forEach(alg => kexAlgs.add(alg));
		if (s.uploads) uploads.push(...s.uploads);
		if (s.tunnels) tunnels.push(...s.tunnels);

		const url = s.download?.url;
		if (url) {
			categories.add('21');
			downloadUrl = url;
		}
	}

	const creds = [...credsSet];
	const loginAttempts = creds.length;
	const cmdCount = commands.length;

	if (loginAttempts >= 2) categories.add('18');
	if (proto === 'ssh') categories.add('22');
	if (proto === 'telnet') categories.add('23');
	if (cmdCount) categories.add('20');
	if (!loginAttempts && !cmdCount) categories.add('14');

	return {
		dpt, proto, sshVersion, timestamp, creds, commands,
		categories, downloadUrl, fingerprints: [...fingerprints],
		uploads, tunnels, kexAlgs: [...kexAlgs],
	};
};

const buildComment = ({ serverId, dpt, proto, creds, commands, sshVersion, downloadUrl, fingerprints, uploads, tunnels, kexAlgs }) => {
	const loginAttempts = creds.length;
	const cmdCount = commands.length;
	const lines = [];

	lines.push(`Honeypot ${serverId ? `[${serverId}]` : 'hit'}: ${loginAttempts ? 'Brute-force attack' : 'Unauthorized connection attempt'} detected on ${dpt}/${proto.toUpperCase()}`);

	if (loginAttempts === 1) {
		lines.push(`• Credential used: ${creds[0]}`);
	} else if (loginAttempts > 1) {
		let joined = creds.join(', ');
		if (joined.length > CREDS_LIMIT) joined = joined.slice(0, CREDS_LIMIT).replace(/,[^,]*$/, '') + '...';
		lines.push(`• Credentials: ${joined}`);
	}

	if (loginAttempts) lines.push(`• Number of login attempts: ${loginAttempts}`);
	if (cmdCount) lines.push(`• ${cmdCount} command(s) were executed during the session`);
	if (sshVersion) lines.push(`• Client: ${sshVersion}`);
	if (downloadUrl) lines.push(`• Suspicious file URL: ${downloadUrl}`);
	if (fingerprints.length) lines.push(`• SSH key fingerprints: ${fingerprints.join(', ')}`);
	if (uploads.length) lines.push(`• Uploaded files: ${uploads.join(', ')}`);
	if (tunnels.length) lines.push(`• TCP tunnels: ${tunnels.join(', ')}`);
	if (kexAlgs.length) lines.push(`• Key exchange algorithms: ${kexAlgs.join(', ')}`);

	return lines.join('\n');
};

const flushBuffer = async (srcIp, reportIp) => {
	const buffer = ipBuffers.get(srcIp);
	if (!buffer) return;

	clearTimeout(buffer.timer);
	ipBuffers.delete(srcIp);

	const sessions = buffer.sessions || [];
	if (!sessions.length) return;

	const {
		dpt, proto, sshVersion, timestamp, creds, commands,
		categories, downloadUrl, fingerprints, uploads, tunnels, kexAlgs,
	} = extractSessionData(sessions);

	if (!srcIp || !dpt || !proto) {
		return logger.log(`COWRIE -> Incomplete data for ${srcIp}, discarded`, 2, true);
	}

	const comment = buildComment({
		serverId: SERVER_ID,
		dpt,
		proto,
		creds,
		commands,
		sshVersion,
		downloadUrl,
		fingerprints,
		uploads,
		tunnels,
		kexAlgs,
	});

	await reportIp('COWRIE', { srcIp, dpt, proto, timestamp }, [...categories].join(','), comment);
	logger.log(`### Cowrie: ${srcIp} on ${dpt}/${proto}\n${comment.split('\n').slice(1).join('\n')}`, 0, true);
};

const processCowrieLogLine = async (entry, reportIp) => {
	const ip = entry?.src_ip;
	const sessionId = entry?.session;
	const { eventid } = entry;
	if (!ip || !eventid || !sessionId) return logger.log('COWRIE -> Skipped: missing src_ip, eventid or sessionId', 2, true);

	let buffer = ipBuffers.get(ip);
	if (!buffer) {
		buffer = {
			sessions: [],
			timer: setTimeout(() => flushBuffer(ip, reportIp), REPORT_DELAY),
		};
		ipBuffers.set(ip, buffer);
	}

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
			fingerprint: null,
			uploads: [],
			tunnels: [],
			kexAlgs: [],
		};
		buffer.sessions.push(session);
	}

	if (session) session.timestamp = entry.timestamp;

	switch (eventid) {
	case 'cowrie.session.connect':
		if (session) {
			session.dpt = entry.dst_port;
			session.proto = entry.protocol;
			logger.log(`COWRIE -> ${ip}/${session.proto}/${session.dpt}: Connect`);
		}
		break;

	case 'cowrie.login.success':
	case 'cowrie.login.failed':
		if (session && (entry.username || entry.password)) {
			session.credentials.set(`${ipSanitizer(entry.username)}:${ipSanitizer(entry.password)}`, true);
			const status = eventid === 'cowrie.login.success' ? 'Connected' : 'Failed login';
			logger.log(`COWRIE -> ${ip}/${session.proto}/${session.dpt}: ${status} » ${entry.username}:${entry.password}`);
		}
		break;

	case 'cowrie.client.version':
		if (session) {
			session.sshVersion = entry.version;
			logger.log(`COWRIE -> ${ip}/${session.proto}/${session.dpt}: SSH version » ${entry.version}`);
		}
		break;

	case 'cowrie.command.input':
		if (session && entry.input) {
			session.commands.push(entry.input);
			logger.log(`COWRIE -> ${ip}/${session.proto}/${session.dpt}: $ ${entry.input}`);
		}
		break;

	case 'cowrie.session.file_download':
		if (session && entry.url) {
			session.commands.push(`[download] ${entry.url}`);
			session.download = { url: entry.url, outfile: entry.outfile };
			logger.log(`COWRIE -> ${ip}/${session.proto}/${session.dpt}: File download » ${entry.url}`);
		}
		break;

	case 'cowrie.client.fingerprint':
		if (session && entry.fingerprint) {
			session.fingerprint = entry.fingerprint;
			logger.log(`COWRIE -> ${ip}/${session.proto}/${session.dpt}: SSH key fingerprint » ${entry.fingerprint}`);
		}
		break;

	case 'cowrie.session.file_upload':
		if (session && entry.filename) {
			session.uploads.push(entry.filename);
			logger.log(`COWRIE -> ${ip}/${session.proto}/${session.dpt}: File upload » ${entry.filename}`);
		}
		break;

	case 'cowrie.direct-tcpip.request':
		if (session && entry.dst_ip && entry.dst_port) {
			const tunnel = `${entry.dst_ip}:${entry.dst_port}`;
			session.tunnels.push(tunnel);
			logger.log(`COWRIE -> ${ip}/${session.proto}/${session.dpt}: TCP tunnel request » ${tunnel}`);
		}
		break;

	case 'cowrie.client.kex':
		if (session && entry.kexAlgs) {
			session.kexAlgs = entry.kexAlgs;
			logger.log(`COWRIE -> ${ip}/${session.proto}/${session.dpt}: Key exchange algorithms » ${entry.kexAlgs.join(', ')}`);
		}
		break;

	case 'cowrie.session.closed':
		logger.log(`COWRIE -> ${ip}/${session?.proto ?? 'unknown'}/${session?.dpt ?? '-'}: Session ${sessionId} closed`);
		break;
	}
};

module.exports = reportIp => {
	if (!fs.existsSync(LOG_FILE)) {
		logger.log(`COWRIE -> Log file not found: ${LOG_FILE}`, 3, true);
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
			logger.log('COWRIE -> Log truncated, offset reset', 2, true);
			return;
		}

		const rl = createInterface({ input: fs.createReadStream(file, { start: fileOffset, encoding: 'utf8' }) });
		rl.on('line', async line => {
			if (!line.length) return;

			let entry;
			try {
				entry = JSON.parse(line);
			} catch (err) {
				logger.log(`COWRIE -> JSON parse error: ${err.message}\nFaulty line: ${JSON.stringify(line)}`, 3, true);
				return;
			}

			try {
				await processCowrieLogLine(entry, reportIp);
			} catch (err) {
				logger.log(err, 3);
			}
		});

		rl.on('close', () => {
			fileOffset = stats.size;
		});
	});

	logger.log('🛡️ COWRIE -> Watcher initialized', 1);
};

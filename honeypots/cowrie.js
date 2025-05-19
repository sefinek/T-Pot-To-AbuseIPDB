const fs = require('node:fs');
const path = require('node:path');
const TailFile = require('@logdna/tail-file');
const split2 = require('split2');
const ipSanitizer = require('../scripts/ipSanitizer.js');
const logIpToFile = require('../scripts/logIpToFile.js');
const logger = require('../scripts/logger.js');
const { COWRIE_LOG_FILE, SERVER_ID } = require('../config.js').MAIN;

const LOG_FILE = path.resolve(COWRIE_LOG_FILE);
const REPORT_DELAY = SERVER_ID === 'development' ? 30 * 1000 : 10 * 60 * 1000;

const CREDS_LIMIT = 900;
const ipBuffers = new Map();

const extractSessionData = sessions => {
	const credsSet = new Set();
	const commands = [];
	const categories = new Set(['15']);
	const fingerprints = new Set();
	const uploads = new Set();
	const tunnels = new Set();

	let dpt = null, proto = null, sshVersion = null, timestamp = null;
	const downloadUrls = new Set();

	for (const s of sessions) {
		dpt ??= s.dpt;
		proto ??= s.proto;
		sshVersion ??= s.sshVersion;
		timestamp ??= s.timestamp;

		s.credentials?.forEach((_, cred) => credsSet.add(cred));
		commands.push(...s.commands);

		if (s.fingerprint) fingerprints.add(s.fingerprint);
		if (s.uploads) s.uploads.forEach(f => uploads.add(f));
		if (s.tunnels) s.tunnels.forEach(t => tunnels.add(t));
		if (s.download?.url) {
			categories.add('21');
			downloadUrls.add(s.download.url);
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
		categories, downloadUrls: [...downloadUrls],
		fingerprints: [...fingerprints],
		uploads: [...uploads],
		tunnels: [...tunnels],
	};
};

const buildComment = ({ serverId, dpt, proto, creds, commands, sshVersion, downloadUrls, fingerprints, uploads, tunnels }, full = false) => {
	const loginAttempts = creds.length;
	const cmdCount = commands.length;
	const lines = [];

	lines.push(`Honeypot ${serverId ? `[${serverId}]` : 'hit'}: ${loginAttempts ? 'Brute-force attack' : 'Unauthorized connection attempt'} detected on ${dpt}/${proto.toUpperCase()}`);

	if (loginAttempts === 1) {
		lines.push(`• Credential used: ${creds[0]}`);
	} else if (loginAttempts > 1) {
		let joined = creds.join(', ');
		if (!full && joined.length > CREDS_LIMIT) joined = joined.slice(0, CREDS_LIMIT).replace(/,[^,]*$/, '') + '...';
		lines.push(`• Credentials: ${joined}`);
	}

	if (loginAttempts) lines.push(`• Number of login attempts: ${loginAttempts}`);
	if (cmdCount) lines.push(`• ${cmdCount} command(s) were executed during the session`);
	if (sshVersion) lines.push(`• Client: ${sshVersion}`);
	if (downloadUrls.length) lines.push(`• Suspicious file URLs: ${downloadUrls.join(', ')}`);
	if (fingerprints.length) lines.push(`• SSH key fingerprints: ${fingerprints.join(', ')}`);
	if (uploads.length) lines.push(`• Uploaded files: ${uploads.join(', ')}`);
	if (tunnels.length) lines.push(`• TCP tunnels: ${tunnels.join(', ')}`);

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
		categories, downloadUrls, fingerprints, uploads, tunnels,
	} = extractSessionData(sessions);

	if (!srcIp || !dpt || !proto) {
		return logger.log(`COWRIE -> Incomplete data for ${srcIp}, discarded`, 2, true);
	}

	const shortComment = buildComment({ serverId: SERVER_ID, dpt, proto, creds, commands, sshVersion, downloadUrls, fingerprints, uploads, tunnels }, false);
	const [, ...restLines] = shortComment.split('\n');
	await reportIp('COWRIE', { srcIp, dpt, proto, timestamp }, [...categories].join(','), shortComment);

	await logger.log(`\n${restLines.join('\n')}`);
	await logger.webhook(`### Cowrie: ${srcIp} on ${dpt}/${proto}\n${restLines.join('\n')}`);

	logIpToFile(srcIp, { honeypot: 'COWRIE', comment: buildComment({ serverId: SERVER_ID, dpt, proto, creds, commands, sshVersion, downloadUrls, fingerprints, uploads, tunnels }, true) });
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
			lastSeen: Date.now(),
		};
		ipBuffers.set(ip, buffer);
	} else {
		buffer.lastSeen = Date.now();
	}

	let session = buffer.sessions.find(s => s.sessionId === sessionId);
	if (!session && eventid !== 'cowrie.session.closed') {
		session = {
			sessionId,
			srcIp: ip,
			dpt: null,
			proto: null,
			timestamp: null,
			credentials: new Map(),
			commands: [],
			sshVersion: null,
			download: null,
			fingerprint: null,
			uploads: [],
			tunnels: [],
		};
		buffer.sessions.push(session);
	}

	switch (eventid) {
	case 'cowrie.session.connect':
		if (session) {
			session.dpt = entry.dst_port;
			session.proto = entry.protocol;
			session.timestamp = entry.timestamp;
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

	case 'cowrie.session.closed':
		logger.log(`COWRIE -> ${ip}/${session?.proto ?? 'unknown'}/${session?.dpt ?? '-'}: Session ${sessionId} closed`);
		break;
	}
};

module.exports = reportIp => {
	if (!fs.existsSync(LOG_FILE)) {
		return logger.log(`COWRIE -> Log file not found: ${LOG_FILE}`, 3, true);
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
				return logger.log(`COWRIE -> JSON parse error: ${err.message}\nFaulty line: ${JSON.stringify(line)}`, 3, true);
			}

			try {
				await processCowrieLogLine(entry, reportIp);
			} catch (err) {
				logger.log(err, 3);
			}
		});

	// Clean buffer
	setInterval(() => {
		const now = Date.now();
		for (const [ip, buffer] of ipBuffers.entries()) {
			if (now - buffer.lastSeen > 30 * 60 * 1000) {
				clearTimeout(buffer.timer);
				ipBuffers.delete(ip);
				logger.log(`COWRIE -> Cleaned up stale session buffer for ${ip}`, 2, true);
			}
		}
	}, 15 * 60 * 1000);

	logger.log('🛡️ COWRIE » Watcher initialized', 1);
	return { tail, flush: () => flushBuffer(null, reportIp) };
};
const fs = require('node:fs');
const path = require('node:path');
const chokidar = require('chokidar');
const { createInterface } = require('node:readline');
const log = require('../utils/log.js');
const { getServerIPs } = require('../services/ipFetcher.js');
const { COWRIE_LOG_FILE, SERVER_ID } = require('../config.js').MAIN;

const LOG_FILE = path.resolve(COWRIE_LOG_FILE);
let fileOffset = 0;

const sessions = new Map();
const FLUSH_INTERVAL = SERVER_ID === 'development' ? 30 * 1000 : 5 * 60 * 1000;

const flushSession = async (sessionId, report) => {
	const session = sessions.get(sessionId);
	if (!session) return;

	clearTimeout(session.timer);
	sessions.delete(sessionId);

	const { srcIp, port, proto, timestamp, sshVersion, credentials, commands } = session;
	if (!srcIp || !port || !proto) return log(1, `COWRIE -> Incomplete session for ${srcIp}, discarded`);

	const creds = [...credentials.keys()];
	const loginAttempts = creds.length;
	const cmdCount = commands.length;

	const categories = ['15'];
	if (loginAttempts >= 2) categories.push('18');
	if (proto === 'ssh') categories.push('22');
	if (proto === 'telnet') categories.push('23');
	if (cmdCount > 0) categories.push('20');
	if (loginAttempts === 0 && cmdCount === 0) categories.push('14');

	const lines = [];
	if (loginAttempts >= 2) {
		lines.push(`Honeypot [${SERVER_ID}]: A ${proto.toUpperCase()} brute-force attack was detected on port ${port}`);
		lines.push(`• Number of login attempts: ${loginAttempts}`);
		lines.push(`• Credentials used: ${creds.join(', ')}`);
	} else {
		lines.push(`Honeypot [${SERVER_ID}]: An unauthorized ${proto.toUpperCase()} connection attempt was detected on port ${port}`);
		if (loginAttempts === 1) lines.push(`• Credential used: ${creds[0]}`);
	}

	if (cmdCount > 0) lines.push(`• ${cmdCount} command(s) were executed during the session`);
	if (sshVersion) lines.push(`• SSH version: ${sshVersion}`);

	await report('COWRIE', {
		srcIp,
		dpt: port,
		service: proto.toUpperCase(),
		timestamp,
	}, categories.join(','), lines.join('\n'));
};

const processCowrieLogLine = async (entry, report) => {
	const ip = entry?.src_ip;
	const sessionId = entry?.session;
	const { eventid } = entry;
	if (!ip || !eventid || !sessionId) return log(1, 'COWRIE -> Skipped: missing src_ip, eventid or sessionId');

	let session = sessions.get(sessionId);
	if (!session && eventid !== 'cowrie.session.closed') {
		session = {
			srcIp: ip,
			port: entry.dst_port,
			proto: entry.protocol,
			timestamp: entry.timestamp,
			credentials: new Map(),
			commands: [],
			sshVersion: null,
			timer: setTimeout(() => flushSession(sessionId, report), FLUSH_INTERVAL),
		};
		sessions.set(sessionId, session);
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

	case 'cowrie.login.success': case 'cowrie.login.failed':
		if (session && (entry.username || entry.password)) {
			const myIps = getServerIPs();
			const ipPattern = new RegExp(myIps.map(i => i.replace(/\./g, '\\.')).join('|'), 'g');
			session.credentials.set(`${entry.username.replace(ipPattern, '[SOME-IP]')}:${entry.password.replace(ipPattern, '[SOME-IP]')}`, true);
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

	case 'cowrie.session.closed':
		log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: Session ${sessionId} closed`);
		await flushSession(sessionId, report);
		break;
	}
};

module.exports = (report, abuseIPDBRateLimited) => {
	if (abuseIPDBRateLimited) return;
	if (!fs.existsSync(LOG_FILE)) {
		log(2, `COWRIE -> Log file not found: ${LOG_FILE}`);
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
			return log(0, 'COWRIE -> Log truncated, offset reset');
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
				await processCowrieLogLine(entry, report);
			} catch (err) {
				log(2, err);
			}
		});
		rl.on('close', () => fileOffset = stats.size);
	});

	log(0, '🛡️ COWRIE -> Watcher initialized');
};
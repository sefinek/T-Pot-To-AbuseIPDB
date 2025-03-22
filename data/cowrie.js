const fs = require('node:fs');
const path = require('node:path');
const chokidar = require('chokidar');
const readline = require('node:readline');
const log = require('../utils/log.js');
const { COWRIE_LOG_FILE, SERVER_ID } = require('../config.js').MAIN;

const LOG_FILE = path.resolve(COWRIE_LOG_FILE);
let fileOffset = 0;

const sessions = new Map();
const FLUSH_INTERVAL = SERVER_ID === 'development' ? 30 * 1000 : 5 * 60 * 1000;

const flushSession = async (sessionId, report) => {
	const session = sessions.get(sessionId);
	if (!session) return;

	clearTimeout(session.timer);

	if (!session.srcIp || !session.port || !session.proto) {
		sessions.delete(sessionId);
		return log(1, `COWRIE -> Incomplete session for ${session.srcIp}, discarded`);
	}

	const loginAttempts = session.credentials.size;
	const categories = ['15']; // Hacking
	if (loginAttempts > 1) categories.push('18'); // Brute-Force

	if (session.proto === 'ssh') {
		categories.push('22'); // SSH abuse
	} else if (session.proto === 'telnet') {
		categories.push('23'); // IoT Targeted
	}

	if (session.commands.length > 0) categories.push('20'); // Exploited host

	let comment = `Honeypot [${SERVER_ID}]: ${session.port}/${session.proto}` + (loginAttempts > 1 ? ' brute-force' : '') + ';';
	if (session.sshVersion) comment += ` SSH version: ${session.sshVersion};`;
	if (loginAttempts > 0) {
		comment += ` Logins: ${loginAttempts} attempts;`;
		comment += ` Credentials: ${[...session.credentials.keys()].join(', ')};`;
	}
	if (session.commands.length > 0) comment += ` Commands executed: ${session.commands.length};`;

	await report('COWRIE', {
		srcIp: session.srcIp,
		dpt: session.port,
		service: session.proto.toUpperCase(),
		timestamp: session.timestamp,
	}, categories.join(','), comment.trim());

	sessions.delete(sessionId);
};

const processCowrieLogLine = async (entry, report) => {
	const ip = entry?.src_ip;
	const sessionId = entry?.session;
	const { eventid } = entry;
	if (!ip || !eventid || !sessionId) return log(1, 'COWRIE -> Skipped: missing src_ip, session or eventid');

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
			log(0, `COWRIE -> ${ip}: Connect (${session.port}/${session.proto})`);
		}
		break;

	case 'cowrie.login.success':
	case 'cowrie.login.failed':
		if (session && (entry.username || entry.password)) {
			session.credentials.set(`${entry.username}:${entry.password}`, true);
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
		if (session) {
			log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: Session closed`);
		} else {
			log(0, `COWRIE -> ${ip}: Session closed (session not found)`);
		}
		await flushSession(sessionId, report);
		break;
	}
};

module.exports = report => {
	if (!fs.existsSync(LOG_FILE)) {
		log(2, `COWRIE -> Log file not found: ${LOG_FILE}`);
		return;
	}

	fileOffset = fs.statSync(LOG_FILE).size;

	chokidar.watch(LOG_FILE, { persistent: true, ignoreInitial: true }).on('change', file => {
		const stats = fs.statSync(file);
		if (stats.size < fileOffset) {
			fileOffset = 0;
			log(0, 'COWRIE -> Log truncated, offset reset');
		}

		const rl = readline.createInterface({ input: fs.createReadStream(file, { start: fileOffset, encoding: 'utf8' }) });
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
				log(2, `COWRIE -> ${err.message}`);
			}
		});
		rl.on('close', () => fileOffset = stats.size);
	});

	log(0, '🛡️ COWRIE -> Watcher initialized');
};
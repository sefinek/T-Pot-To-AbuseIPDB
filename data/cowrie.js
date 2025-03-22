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

const flushSession = async (ip, report) => {
	const session = sessions.get(ip);
	if (!session) return;

	clearTimeout(session.timer);

	if (!session.srcIp || !session.port || !session.proto) {
		sessions.delete(ip);
		return log(1, `COWRIE -> Incomplete session for ${ip}, discarded`);
	}

	let category = '14';
	let comment = `Honeypot [${SERVER_ID}]: ${session.port}/${session.proto} brute-force;`;

	if (session.sshVersion) comment += ` SSH version: ${session.sshVersion};`;

	if (session.failedLogins.length > 0) {
		category += ',18';
		if (session.proto === 'ssh') category += ',22';
		if (session.proto === 'telnet') category += ',23';
	}

	const loginAttempts = session.failedLogins.length + session.successfulLogins.length;
	if (loginAttempts > 0) {
		comment += ` Logins: ${loginAttempts} attempts;`;
	}

	if (session.commands.length > 0) {
		category += ',15';
		comment += ` Commands executed (${session.commands.length});`;
	}

	await report('COWRIE', {
		srcIp: session.srcIp,
		dpt: session.port,
		service: session.proto.toUpperCase(),
		timestamp: session.timestamp,
	}, category, comment.trim());

	sessions.delete(ip);
};

const processCowrieLogLine = async (line, report) => {
	let entry;

	try {
		entry = JSON.parse(line);
	} catch (err) {
		log(2, `COWRIE -> JSON parse error: ${err.message}`);
		return;
	}

	const ip = entry?.src_ip;
	const { eventid } = entry;
	if (!ip || !eventid) {
		log(1, 'COWRIE -> Skipped: missing src_ip or eventid');
		return;
	}

	let session = sessions.get(ip);
	if (!session) {
		const { dst_port, protocol } = entry;
		if (!dst_port || !protocol) {
			log(1, `COWRIE -> Skipped: missing dst_port or protocol for IP ${ip}`);
			return;
		}

		session = {
			srcIp: ip,
			port: dst_port,
			proto: protocol,
			timestamp: entry.timestamp,
			failedLogins: [],
			successfulLogins: [],
			commands: [],
			sshVersion: null,
			timer: setTimeout(() => flushSession(ip, report), FLUSH_INTERVAL),
		};
		sessions.set(ip, session);
	}

	session.timestamp = entry.timestamp || session.timestamp;

	switch (eventid) {
	case 'cowrie.session.connect':
		session.port = entry.dst_port || session.port;
		session.proto = entry.protocol || session.proto;
		log(0, `COWRIE -> ${ip}: Connect (${session.port}/${session.proto})`);
		break;

	case 'cowrie.login.success':
		if (entry.username || entry.password) {
			session.successfulLogins.push({ username: entry.username, password: entry.password });
			log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: Successful login => ${entry.username}:${entry.password}`);
		} else {
			log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: Successfully connected`);
		}
		break;

	case 'cowrie.client.version':
		session.sshVersion = entry.version;
		log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: SSH version => ${entry.version}`);
		break;

	case 'cowrie.login.failed':
		if (entry.username || entry.password) {
			session.failedLogins.push({ username: entry.username, password: entry.password });
			log(1, `COWRIE -> ${ip}/${session.proto}/${session.port}: Failed login => ${entry.username}:${entry.password}`);
		}
		break;

	case 'cowrie.command.input':
		if (entry.input) {
			session.commands.push(entry.input);
			log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: $ ${entry.input}`);
		}
		break;

	case 'cowrie.session.closed':
		log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: Session closed`);
		await flushSession(ip, report);
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
			try {
				await processCowrieLogLine(line, report);
			} catch (err) {
				log(2, `COWRIE -> ${err.message}`);
			}
		});
		rl.on('close', () => fileOffset = stats.size);
	});

	log(0, '🛡️ COWRIE -> Watcher initialized');
};
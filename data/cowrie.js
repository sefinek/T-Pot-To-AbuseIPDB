const fs = require('node:fs');
const path = require('node:path');
const chokidar = require('chokidar');
const readline = require('node:readline');
const log = require('../utils/log.js');
const { COWRIE_LOG_FILE, SERVER_ID } = require('../config.js').MAIN;

const LOG_FILE = path.resolve(COWRIE_LOG_FILE);
let fileOffset = 0;

const sessions = new Map();
const FLUSH_INTERVAL = 30 * 1000;

const flushSession = async (ip, report) => {
	const session = sessions.get(ip);
	if (!session || !session.srcIp || !session.port) return;

	let category = '14';
	let comment = `Honeypot [${SERVER_ID}]: ${session.proto.toUpperCase()} brute-force from ${session.srcIp} to port ${session.port}; `;

	if (session.sshVersion) comment += `SSH version: ${session.sshVersion}; `;

	if (session.failedLogins.length > 0) {
		category += ',18';
		if (session.proto === 'ssh') category += ',22';
		if (session.proto === 'telnet') category += ',23';

		const creds = session.failedLogins.map(entry => `'${entry.username}:${entry.password}'`).join(', ');
		comment += `Failed logins: ${creds}; `;
	}

	if (session.commands.length > 0) {
		category += ',15';
		comment += `Commands executed (${session.commands.length}); `;
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
	try {
		const entry = JSON.parse(line);
		const ip = entry.src_ip;
		if (!ip) return;

		let session = sessions.get(ip);
		if (!session) {
			if (!entry.dst_port || !entry.protocol) {
				log(0, `COWRIE -> Skipped: missing dst_port or protocol for IP ${ip}`);
				return;
			}

			session = {
				srcIp: ip,
				port: entry.dst_port,
				proto: entry.protocol,
				timestamp: entry.timestamp,
				failedLogins: [],
				commands: [],
				sshVersion: null,
				hassh: null,
				timer: setTimeout(() => flushSession(ip, report), FLUSH_INTERVAL),
			};
			sessions.set(ip, session);
		}

		session.timestamp = entry.timestamp;

		switch (entry.eventid) {
		case 'cowrie.session.connect':
			session.port = entry.dst_port;
			session.proto = entry.protocol;
			log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: Connect`);
			break;
		case 'cowrie.login.success':
			if (entry.username || entry.password) {
				session.failedLogins.push({ username: entry.username, password: entry.password });
				log(1, `COWRIE -> ${ip}/${session.proto}/${session.port}: Failed login => ${entry.username}:${entry.password}`);
			}

			log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: Successfully connected`);
			break;
		case 'cowrie.client.version':
			session.sshVersion = entry.version;
			log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: SSH version => ${entry.version}`);
			break;
		case 'cowrie.client.kex':
			session.hassh = entry.hassh;
			log(0, `COWRIE -> ${ip}/${session.proto}/${session.port}: SSH fingerprint => ${entry.hassh}`);
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
			break;
		}
	} catch (err) {
		log(2, `COWRIE -> ${err.message}`);
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
		rl.on('line', line => processCowrieLogLine(line, report));
		rl.on('close', () => fileOffset = stats.size);
	});

	log(0, '🛡️ COWRIE -> Watcher initialized');
};
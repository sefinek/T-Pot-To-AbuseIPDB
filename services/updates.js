const { SERVER_ID, AUTO_UPDATE_SCHEDULE } = require('../config.js').MAIN;

const simpleGit = require('simple-git');
const { CronJob } = require('cron');
const restartApp = require('./reloadApp.js');
const log = require('../utils/log.js');
const discordWebhooks = require('./discord.js');

const git = simpleGit();

const pull = async () => {
	await discordWebhooks(4, 'Updating the local repository in progress `(git pull)`...');

	log(0, 'Updating the repository...');
	try {
		const { summary } = await git.pull();
		log(0, `Changes: ${summary.changes}; Deletions: ${summary.deletions}; Insertions: ${summary.insertions}`);
		await discordWebhooks(4, `**Changes:** ${summary.changes}; **Deletions:** ${summary.deletions}; **Insertions:** ${summary.insertions}`);
	} catch (err) {
		return log(2, err);
	}

	log(0, 'Updating submodules...');
	try {
		await git.subModule(['update', '--init', '--recursive']);
		await git.subModule(['foreach', 'git fetch && git checkout $(git rev-parse --abbrev-ref HEAD) && git pull origin main']);
	} catch (err) {
		log(2, err);
	}
};

const pullAndRestart = async () => {
	if (SERVER_ID === 'development') return;

	try {
		await pull();
		await restartApp();
	} catch (err) {
		log(2, err);
	}
};

// https://crontab.guru
new CronJob(AUTO_UPDATE_SCHEDULE, pullAndRestart, null, true, 'UTC');

module.exports = pull;
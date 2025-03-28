const { CronJob } = require('cron');
const { AUTO_UPDATE_SCHEDULE } = require('../config.js').MAIN;
const log = require('../utils/log.js');

const checkForUpdates = async () => {

};

// https://crontab.guru
new CronJob(AUTO_UPDATE_SCHEDULE, checkForUpdates, null, true, 'UTC');
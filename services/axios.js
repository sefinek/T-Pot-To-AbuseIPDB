const axios = require('axios');
const { version, repoName, repoURL } = require('../utils/repo.js');

axios.defaults.headers.common = {
	'User-Agent': `Mozilla/5.0 (compatible; ${repoName}/${version}; +${repoURL})`,
	'Accept': 'application/json',
	'Cache-Control': 'no-cache',
	'Connection': 'keep-alive',
};

axios.defaults.timeout = 50000;

module.exports = axios;
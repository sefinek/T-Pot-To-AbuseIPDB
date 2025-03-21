const { version, homepage } = require('../package.json');

const match = homepage.match(/github\.com\/([^\\/]+)\/([^#\\/]+)/);
const repoFull = match ? `${match[1]}/${match[2]}` : 'Missing/data';
const repoName = match ? match[2] : 'Unknown';
const repoURL = homepage.split('#')[0] || '';

module.exports = { version, repoFull, repoName, repoURL };
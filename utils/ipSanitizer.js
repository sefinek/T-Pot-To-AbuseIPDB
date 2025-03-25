const { getServerIPs } = require('../services/ipFetcher.js');

const ipPattern = (() => {
	const ips = getServerIPs();
	if (!ips.length) return null;
	const escaped = ips.map(i => i.replace(/[.:\\[\](){}^$*+?|]/g, '\\$&'));
	return new RegExp(escaped.join('|'), 'g');
})();

module.exports = str => ipPattern ? str.replace(ipPattern, '[SOME-IP]') : str;
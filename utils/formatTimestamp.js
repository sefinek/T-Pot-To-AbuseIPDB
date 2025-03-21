module.exports = iso => {
	try {
		const date = new Date(iso);
		if (isNaN(date.getTime())) throw new Error('Invalid Date');

		return date.toISOString().split('.')[0] + 'Z';
	} catch {
		return new Date().toISOString().split('.')[0] + 'Z';
	}
};
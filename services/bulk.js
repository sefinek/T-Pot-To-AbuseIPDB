const FormData = require('form-data');
const { parse } = require('csv-parse/sync');
const { stringify } = require('csv-stringify/sync');
const fs = require('node:fs');
const path = require('node:path');
const axios = require('../services/axios.js');
const { saveReportedIPs, markIPAsReported } = require('../services/cache.js');
const log = require('../utils/log.js');
const { ABUSEIPDB_API_KEY } = require('../config.js').MAIN;

const BULK_REPORT_BUFFER = new Map();
const BUFFER_FILE = path.join(__dirname, '..', 'tmp', 'bulk-report-buffer.csv');
const ABUSE_STATE = { isLimited: false, isBuffering: false, sentBulk: false };

const saveBufferToFile = () => {
	if (!BULK_REPORT_BUFFER.size) return;

	const records = [];
	for (const [ip, entry] of BULK_REPORT_BUFFER.entries()) {
		const safeComment = entry.comment.substring(0, 930);
		records.push([ip, entry.categories, new Date(entry.timestamp).toISOString(), safeComment]);
	}

	try {
		const output = stringify(records, { header: true, columns: ['IP', 'Categories', 'ReportDate', 'Comment'], quoted: true });
		fs.writeFileSync(BUFFER_FILE, output);
	} catch (err) {
		log(1, `❌ Failed to write buffer file: ${err.message}`, 1);
	}
};

const loadBufferFromFile = () => {
	if (!fs.existsSync(BUFFER_FILE)) return;

	const fileContent = fs.readFileSync(BUFFER_FILE, 'utf-8');
	let loaded = 0;

	try {
		const records = parse(fileContent, { columns: false, from_line: 2, skip_empty_lines: true, trim: true });
		for (const record of records) {
			const [ip, categories, timestamp, comment] = record;
			if (!ip || !timestamp) continue;

			BULK_REPORT_BUFFER.set(ip, { categories, timestamp: new Date(timestamp).getTime(), comment });
			loaded++;
		}

		log(0, `📂 Loaded ${loaded} IPs from ${BUFFER_FILE}`, 1);
	} catch (err) {
		log(1, `❌ Failed to parse buffer file: ${err.message}`, 1);
	} finally {
		if (fs.existsSync(BUFFER_FILE)) fs.unlinkSync(BUFFER_FILE);
	}
};

const sendBulkReport = async () => {
	if (!BULK_REPORT_BUFFER.size) return;

	const records = [];
	for (const [ip, entry] of BULK_REPORT_BUFFER.entries()) {
		const cleanComment = entry.comment.replace(/\n/g, ' ').substring(0, 1024);

		records.push([
			ip,
			entry.categories,
			new Date(entry.timestamp ?? Date.now()).toISOString(),
			cleanComment,
		]);
	}

	try {
		const payload = stringify(records, {
			header: true,
			columns: ['IP', 'Categories', 'ReportDate', 'Comment'],
			quoted: true,
		});

		const form = new FormData();
		form.append('csv', Buffer.from(payload), {
			filename: 'report.csv',
			contentType: 'text/csv',
		});

		const { data } = await axios.post('https://api.abuseipdb.com/api/v2/bulk-report', form, {
			headers: {
				Key: ABUSEIPDB_API_KEY,
				...form.getHeaders(),
			},
		});

		const saved = data?.data?.savedReports ?? 0;
		const failed = data?.data?.invalidReports?.length ?? 0;

		log(0, `🤮 Sent bulk report (${BULK_REPORT_BUFFER} IPs): ${saved} accepted, ${failed} rejected`, 1);
		if (failed > 0) {
			data.data.invalidReports.forEach(fail => {
				log(1, `Rejected in bulk report [Row ${fail.rowNumber}] ${fail.input} -> ${fail.error}`);
			});
		}

		for (const ip of BULK_REPORT_BUFFER.keys()) markIPAsReported(ip);
		saveReportedIPs();
		BULK_REPORT_BUFFER.clear();
		if (fs.existsSync(BUFFER_FILE)) fs.unlinkSync(BUFFER_FILE);
		log(0, '🧹 Buffer file deleted');
		ABUSE_STATE.sentBulk = true;
	} catch (err) {
		log(1, `❌ Failed to send bulk report to AbuseIPDB: ${err.stack}`, 1);
	}
};

module.exports = {
	saveBufferToFile,
	loadBufferFromFile,
	sendBulkReport,
	BULK_REPORT_BUFFER,
};
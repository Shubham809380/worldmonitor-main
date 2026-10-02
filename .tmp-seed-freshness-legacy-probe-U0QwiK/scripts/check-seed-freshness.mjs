import { parseArgs } from 'node:util';
import { writeFileSync } from 'node:fs';
const { values } = parseArgs({ options: { 'json-output': { type: 'string' } } });
writeFileSync(values['json-output'], JSON.stringify({ version: 1, report: { failed: true } }));
process.exitCode = 1;
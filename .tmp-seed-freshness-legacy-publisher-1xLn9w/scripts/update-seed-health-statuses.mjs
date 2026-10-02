import { writeFileSync } from 'node:fs';
writeFileSync(process.env.ARGS_LOG, JSON.stringify(process.argv.slice(2)));

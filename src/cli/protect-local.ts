import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { privateDirectory, protectPrivatePath } from '../security/private-storage.js';

protectPrivatePath(resolve('.'));
privateDirectory('.data');
protectPrivatePath('.data', true);
if (existsSync('.env')) protectPrivatePath('.env');
console.log('Protected the current service workspace, .data and .env for the running identity.');

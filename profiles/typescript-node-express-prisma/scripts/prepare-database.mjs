import { mkdir, open } from 'node:fs/promises';
import path from 'node:path';

const value = process.env.DATABASE_URL?.trim();
if (!value) throw new Error('MISSING_DATABASE_URL');
if (!value.startsWith('file:')) process.exit(0);
const raw = value.slice('file:'.length);
if (!raw || raw.includes('\0')) throw new Error('INVALID_SQLITE_DATABASE_URL');
const schemaDirectory = path.resolve('prisma');
const target = path.isAbsolute(raw) ? path.resolve(raw) : path.resolve(schemaDirectory, raw);
await mkdir(path.dirname(target), { recursive: true });
const handle = await open(target, 'a', 0o600);
await handle.close();

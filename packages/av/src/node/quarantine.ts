import { createHash, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readdir, readFile, rm, unlink, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import type { AvDetection } from '../types';

/**
 * Quarantine moves a file somewhere it cannot run. The bytes are XORed with a
 * fixed key so the stored copy is not a working executable, does not match
 * signatures (other scanners will not keep re-flagging it), and can be put
 * back exactly as it was.
 */

const KEY = 0xa5;

export interface QuarantineEntry {
  id: string;
  originalPath: string;
  sha256: string;
  size: number;
  detections: Array<Pick<AvDetection, 'id' | 'name' | 'engine' | 'impact'>>;
  quarantinedAt: string;
}

export function quarantineDir(home = homedir()): string {
  return process.env.CRUSHAV_QUARANTINE_DIR ?? join(home, '.threatcrush', 'quarantine');
}

function xor(buf: Buffer): Buffer {
  const out = Buffer.allocUnsafe(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ KEY;
  return out;
}

export async function quarantineFile(path: string, detections: AvDetection[] = [], dir = quarantineDir()): Promise<QuarantineEntry> {
  const data = await readFile(path);
  const sha256 = createHash('sha256').update(data).digest('hex');
  const id = `${new Date().toISOString().replace(/[-:T.Z]/g, '').slice(0, 14)}-${randomBytes(4).toString('hex')}`;
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const entry: QuarantineEntry = {
    id,
    originalPath: path,
    sha256,
    size: data.length,
    detections: detections.map(({ id: did, name, engine, impact }) => ({ id: did, name, engine, impact })),
    quarantinedAt: new Date().toISOString(),
  };
  const bin = join(dir, `${id}.bin`);
  await writeFile(bin, xor(data), { mode: 0o600 });
  // Verify the stored copy before deleting the original, so a full disk never loses the file.
  const check = xor(await readFile(bin));
  if (createHash('sha256').update(check).digest('hex') !== sha256) {
    await rm(bin, { force: true });
    throw new Error('quarantine copy did not verify; original left in place');
  }
  await writeFile(join(dir, `${id}.json`), JSON.stringify(entry, null, 2), { mode: 0o600 });
  await unlink(path);
  return entry;
}

export async function listQuarantine(dir = quarantineDir()): Promise<QuarantineEntry[]> {
  if (!existsSync(dir)) return [];
  const out: QuarantineEntry[] = [];
  for (const f of await readdir(dir)) {
    if (!f.endsWith('.json')) continue;
    try {
      out.push(JSON.parse(await readFile(join(dir, f), 'utf8')) as QuarantineEntry);
    } catch {
      /* ignore a damaged record */
    }
  }
  return out.sort((a, b) => b.quarantinedAt.localeCompare(a.quarantinedAt));
}

async function entryOf(id: string, dir: string): Promise<QuarantineEntry> {
  if (!/^[\w-]+$/.test(id)) throw new Error(`bad quarantine id: ${id}`);
  const p = join(dir, `${id}.json`);
  if (!existsSync(p)) throw new Error(`no quarantined file with id ${id}`);
  return JSON.parse(await readFile(p, 'utf8')) as QuarantineEntry;
}

/** Put a file back. Refuses to overwrite anything already at the destination. */
export async function restoreQuarantined(id: string, to?: string, dir = quarantineDir()): Promise<string> {
  const entry = await entryOf(id, dir);
  const dest = to ?? entry.originalPath;
  const data = xor(await readFile(join(dir, `${id}.bin`)));
  await mkdir(dirname(dest), { recursive: true });
  // 'wx' creates exclusively: the existence check and the write are one atomic step.
  try {
    await writeFile(dest, data, { flag: 'wx' });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'EEXIST') throw new Error(`${dest} already exists; pass another destination`);
    throw e;
  }
  await rm(join(dir, `${id}.bin`), { force: true });
  await rm(join(dir, `${id}.json`), { force: true });
  return dest;
}

export async function deleteQuarantined(id: string, dir = quarantineDir()): Promise<void> {
  await entryOf(id, dir);
  await rm(join(dir, `${id}.bin`), { force: true });
  await rm(join(dir, `${id}.json`), { force: true });
}

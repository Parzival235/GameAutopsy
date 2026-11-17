import { crcOf, MiB } from './formats.mjs?v=0.13.0';
import { openMember, readMember } from './archive-members.mjs?v=0.13.0';
import { storedZip } from './stored-zip.mjs?v=0.13.0';

export const exportLimit = Object.freeze({ entries: 100, payloadBytes: 64 * MiB, workBytes: 192 * MiB });
const maxPathUnits = 512 * 1024;
const encoder = new TextEncoder();
const windowsDevice = /^(?:con|prn|aux|nul|com[0-9]|lpt[0-9]) *(?:\.|$)/i;

function safePart(part) {
  const cleaned = part.normalize('NFKC').replace(/[^\p{L}\p{N}\p{M}. _-]/gu, '_').replace(/^[ .]+|[ .]+$/g, '');
  const short = Array.from(cleaned).slice(0, 48).join('').replace(/[ .]+$/g, '');
  return windowsDevice.test(short) ? '_' + short : short || '_';
}

function safePath(record, files, folders) {
  const parts = record.name.replace(/^res:\/\//, '').split(/[\\/]+/).filter(Boolean).map(safePart);
  const path = parts.join('/');
  const leaf = parts.at(-1) ?? 'entry';
  const route = record.route.slice(0, -1);
  const group = route.length ? 'archive-' + route.join('-') : 'root';
  const memberPath = path && encoder.encode(path).length <= 168 ? path : leaf;
  const name = 'files/' + group + '/' + memberPath;
  const key = name.toLowerCase();
  const prefixes = [];
  for (let index = key.indexOf('/'); index !== -1; index = key.indexOf('/', index + 1)) {
    prefixes.push(key.slice(0, index));
  }
  if (files.has(key) || folders.has(key) || prefixes.some(prefix => files.has(prefix))) {
    return 'collisions/' + record.id + '/' + leaf;
  }
  files.add(key);
  for (const prefix of prefixes) folders.add(prefix);
  return name;
}

export async function exportInventory(root, inventory, indices, progress = () => {}) {
  if (!inventory) throw new Error('Index the root archive before exporting entries.');
  if (!Array.isArray(indices) || !indices.length || indices.length > exportLimit.entries) {
    throw new Error('Select between 1 and ' + exportLimit.entries + ' inventory entries.');
  }
  if (!indices.every(id => Number.isInteger(id) && inventory.rows[id]?.id === id)) {
    throw new Error('The selection does not match the current inventory.');
  }
  const ids = [...new Set(indices)].sort((a, b) => a - b);
  const manifest = {
    schema: 'gameautopsy/inventory-export/1', root: root.report.name, format: root.report.format,
    requested: ids.length, payloadBytes: 0, workBytes: 0, limits: exportLimit, entries: [], skipped: []
  };
  const output = [];
  const nodes = [root];
  const activeRoute = [];
  const files = new Set();
  const folders = new Set();
  let pathUnits = 0;

  function charge(size) {
    if (!Number.isSafeInteger(size) || size < 0 || size > exportLimit.workBytes - manifest.workBytes) {
      throw new Error('The batch read budget would be exceeded.');
    }
    manifest.workBytes += size;
  }

  async function findParent(route) {
    const length = route.length - 1;
    let shared = 0;
    while (shared < length && activeRoute[shared] === route[shared]) shared++;
    activeRoute.length = shared;
    nodes.length = shared + 1;
    for (let i = shared; i < length; i++) {
      const parent = nodes.at(-1);
      const child = await openMember(parent, parent.report.rows[route[i]], undefined, charge);
      nodes.push(child);
      activeRoute.push(route[i]);
    }
    return nodes.at(-1);
  }

  for (const [position, id] of ids.entries()) {
    const record = inventory.rows[id];
    const path = [...record.path, record.name];
    const units = path.reduce((total, item) => total + item.length, 0);
    progress({ stage: 'Exporting selected entries', done: position, total: ids.length, unit: 'entries',
      detail: record.name.slice(0, 160) });
    try {
      if (!record.open) throw new Error('The member is available as metadata only.');
      if (record.size > exportLimit.payloadBytes - manifest.payloadBytes) {
        throw new Error('The decoded payload would exceed the 64 MiB download limit.');
      }
      if (units > maxPathUnits - pathUnits) throw new Error('The manifest path text limit would be exceeded.');
      const parent = await findParent(record.route);
      const member = parent.report.rows[record.route.at(-1)];
      if (member?.name !== record.name || member.size !== record.size) {
        throw new Error('The indexed member could not be located.');
      }
      const { blob, source } = await readMember(parent, member, undefined, charge);
      if (blob.size !== record.size) throw new Error('The decoded entry size differs from the index.');
      let crc32 = source.crc32;
      if (crc32 == null) {
        charge(blob.size);
        crc32 = await crcOf(blob);
      }
      const name = safePath(record, files, folders);
      output.push({ name, blob, crc32 });
      manifest.entries.push({ path, route: record.route, output: name, size: blob.size, containerFormat: parent.report.format,
        source, verification: parent.report.format === 'ZIP' ? 'sourceZipCrc32' : 'decodedSize' });
      manifest.payloadBytes += blob.size;
      pathUnits += units;
    } catch (error) {
      manifest.skipped.push({ name: record.name.slice(0, 160), route: record.route, reason: error.message.slice(0, 240) });
    }
  }
  progress({ stage: 'Preparing ZIP download', done: ids.length, total: ids.length, unit: 'entries' });
  if (!output.length) return { output: null, manifest };
  const report = new Blob([JSON.stringify(manifest, null, 2) + '\n'], { type: 'application/json' });
  output.push({ name: 'gameautopsy-manifest.json', blob: report, crc32: await crcOf(report) });
  return { output: storedZip(output), manifest };
}

import { analyze, MiB, openZipMember } from './formats.mjs?v=0.10.0';
import { isCompleteZip } from './compare.mjs?v=0.10.0';

const maxInput = 384 * MiB;
const maxExpanded = 128 * MiB;

function uniqueEntry(node, name, side) {
  if (!isCompleteZip(node.report)) throw new Error(side + ' archive has an incomplete ZIP directory.');
  const matches = node.report.rows.filter(row => row.kind !== 'Directory' && row.name === name);
  if (!matches.length) throw new Error(side + ' archive does not contain that exact entry path.');
  if (matches.length > 1) throw new Error(side + ' archive has duplicate entries at that path.');
  const [entry] = matches;
  if (!entry.open) throw new Error(side + ' entry uses unsupported compression or encryption.');
  return entry;
}

export async function openZipEntryPair(before, after, archivePath, name, progress = () => {}) {
  let left = before;
  let right = after;
  let input = 0;
  let expanded = 0;
  async function openPair(path) {
    const a = uniqueEntry(left, path, 'Baseline');
    const b = uniqueEntry(right, path, 'Candidate');
    for (const entry of [a, b]) {
      input += entry.packed + (entry.method === 8 ? entry.size : 0);
      if (entry.method === 8) expanded += entry.size;
    }
    if (input > maxInput || expanded > maxExpanded) {
      throw new Error('Reopening these entry paths would exceed the 384 MiB input or 128 MiB decoded-data budget.');
    }
    const open = async (node, entry, side) => {
      const detail = side + ' · ' + entry.name;
      progress({ stage: 'Opening comparison entry', detail });
      const opened = await openZipMember(node.blob, entry, update => progress({ ...update, detail }));
      return {
        blob: opened.blob,
        location: { localHeaderOffset: entry.offset, dataOffset: opened.dataOffset, crc32: entry.crc32, method: entry.method }
      };
    };
    const first = await open(left, a, 'Baseline');
    const second = await open(right, b, 'Candidate');
    return [first, second];
  }

  for (const path of archivePath) {
    const [a, b] = await openPair(path);
    left = { blob: a.blob, report: await analyze(a.blob, path) };
    right = { blob: b.blob, report: await analyze(b.blob, path) };
  }
  const [a, b] = await openPair(name);
  return {
    before: a.blob, after: b.blob, beforeName: name, afterName: name,
    source: {
      kind: 'zipEntry', archivePath, entry: name,
      baseline: { archive: before.report.name, ...a.location },
      candidate: { archive: after.report.name, ...b.location }
    }
  };
}

import { bytesAt, MiB, openZipMember, zipLocalInfo } from './formats.mjs?v=0.3.0';

const labels = new Map([[0x7109871a, 'APK v2'], [0xf05368c0, 'APK v3'], [0x1b93ad61, 'APK v3.1']]);
const hex = n => '0x' + n.toString(16).toUpperCase();
const view = bytes => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

async function signingBlock(blob, directory) {
  if (directory < 24) return null;
  const footer = await bytesAt(blob, directory - 24, 24);
  if (new TextDecoder().decode(footer.subarray(8)) !== 'APK Sig Block 42') return null;
  const size = view(footer).getBigUint64(0, true);
  if (size <= 24n || size > BigInt(directory - 8)) throw new Error('APK signing block footer size is invalid.');
  const start = directory - Number(size) - 8;
  const head = view(await bytesAt(blob, start, 8));
  if (head.getBigUint64(0, true) !== size) throw new Error('APK signing block size fields disagree.');
  const pairs = [];
  const seen = new Set();
  const end = directory - 24;
  let offset = start + 8;
  while (offset < end) {
    if (pairs.length === 1024 || end - offset < 12) throw new Error('APK signing block pair list is truncated or exceeds its limit.');
    const pair = view(await bytesAt(blob, offset, 12));
    const length = pair.getBigUint64(0, true);
    if (length < 4n || length > BigInt(end - offset - 8)) throw new Error('APK signing block pair length is invalid.');
    const id = pair.getUint32(8, true);
    if (labels.has(id) && seen.has(id)) throw new Error('Duplicate APK signature scheme ID ' + hex(id) + '.');
    seen.add(id);
    pairs.push({ id: hex(id), name: labels.get(id) ?? 'Other ID', offset: offset + 12, size: Number(length) - 4 });
    offset += Number(length) + 8;
  }
  return { offset: start, size: Number(size) + 8, pairs };
}

export async function checkZip(blob, report) {
  const directory = Number(report.details['Central directory']);
  if (report.format !== 'ZIP' || !Number.isSafeInteger(directory)) throw new Error('Open a ZIP with a readable central directory first.');
  const checks = [];
  const add = (status, name, message, offset = null) => checks.push({ status, name, message, offset });
  let signature = null;
  try {
    signature = await signingBlock(blob, directory);
    if (signature) for (const pair of signature.pairs) add('Info', pair.name, pair.id + ' · ' + pair.size + ' bytes', pair.offset);
  } catch (error) {
    add('Error', 'APK signing block', error.message, directory - 24);
  }
  const apk = /\.apk$/i.test(report.name) || report.rows.some(row => row.name === 'AndroidManifest.xml');
  const boundary = signature?.offset ?? directory;
  const names = new Set();
  let count = 0;
  let stored = 0;
  let native = 0;
  let skipped = 0;
  const ranges = [];
  for (const entry of report.rows) {
    if (names.has(entry.name)) add('Warning', entry.name, 'Duplicate path.', entry.central);
    names.add(entry.name);
    if (entry.flags & 0x2041) {
      skipped++;
      continue;
    }
    try {
      const offset = await zipLocalInfo(blob, entry, boundary);
      count++;
      ranges.push({ start: entry.offset, end: offset + entry.packed, name: entry.name });
      if (!apk || entry.method !== 0 || entry.kind === 'Directory') continue;
      stored++;
      if (offset % 4) add('Warning', entry.name, 'Stored payload is not 4-byte aligned.', offset);
      if (/^lib\/[^/]+\/[^/]+\.so$/i.test(entry.name)) {
        native++;
        if (offset % 16384) add('Warning', entry.name, 'Stored native library payload is not 16 KiB aligned.', offset);
      }
    } catch (error) {
      add('Error', entry.name, error.message, entry.offset);
    }
  }
  ranges.sort((a, b) => a.start - b.start);
  let previous;
  for (const range of ranges) {
    if (previous && range.start < previous.end) add('Error', range.name, 'Header or payload overlaps ' + previous.name + '.', range.start);
    if (!previous || range.end > previous.end) previous = range;
  }
  if (report.status !== 'ok' || report.rows.length !== report.details['Declared entries']) {
    add('Warning', 'Central directory', 'Only the entries present in the partial report were checked.', directory);
  }
  if (skipped) add('Info', 'Encrypted entries', skipped + ' local headers skipped.');
  if (apk && !signature) add('Info', 'APK signing block', 'No parsed APK v2/v3 signing block. V1 signatures are outside this check.');
  return {
    localHeadersChecked: count, storedApkEntries: stored, storedNativeLibraries: native,
    signingBlock: signature, checks
  };
}

export async function verifyZipPayloads(blob, report) {
  if (report.format !== 'ZIP') throw new Error('Open a ZIP archive first.');
  const eligible = report.rows.filter(entry => entry.kind !== 'Directory');
  const checks = [];
  let attempted = 0;
  let verified = 0;
  let budget = 256 * MiB;
  for (const entry of eligible) {
    const cost = entry.size + entry.packed;
    if (!entry.open || Math.max(entry.size, entry.packed) > 128 * MiB || cost > budget || attempted === 512) continue;
    budget -= cost;
    attempted++;
    try {
      await openZipMember(blob, entry);
      verified++;
    } catch (error) {
      checks.push({ status: 'Error', name: entry.name, message: error.message, offset: entry.offset });
    }
  }
  return {
    attempted, verified, skipped: eligible.length - attempted,
    completeDirectory: report.status === 'ok' && report.rows.length === report.details['Declared entries'],
    checks
  };
}

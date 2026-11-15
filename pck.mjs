const maxDirectory = 24 * 1024 * 1024;
const maxEntries = 20000;
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

const view = bytes => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
const hex = n => '0x' + n.toString(16).toUpperCase();
const byteHex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');

export async function inspectPck(blob, report, head) {
  if (head.length < 20) throw new Error('Missing PCK header.');
  const header = view(head);
  const u32 = offset => header.getUint32(offset, true);
  const version = u32(4);
  report.details['Format version'] = version;
  report.details['Engine version'] = [8, 12, 16].map(u32).join('.');
  if (version > 4) {
    report.warnings.push('Only the header was read for this PCK format version.');
    return;
  }
  const modern = version >= 2;
  const directoryAtEnd = version >= 3;
  const headerSize = directoryAtEnd ? 40 : modern ? 96 : 84;
  if (head.length < headerSize) throw new Error('Truncated PCK header.');
  const flags = modern ? u32(20) : 0;
  const base = modern ? header.getBigUint64(24, true) : 0n;
  const directory = directoryAtEnd ? header.getBigUint64(32, true) : BigInt(headerSize);
  Object.assign(report.details, { 'Pack flags': hex(flags), 'File base': hex(base), Directory: hex(directory) });
  report.rows.push({ name: 'Header', kind: 'PCK header', offset: 0, size: headerSize });
  if (directory < BigInt(headerSize) || directory + 4n > BigInt(blob.size)) {
    throw new Error('PCK directory offset is outside the pack.');
  }
  const start = Number(directory);
  const count = view(new Uint8Array(await blob.slice(start, start + 4).arrayBuffer())).getInt32(0, true);
  if (count < 0) throw new Error('Invalid PCK file count.');
  report.details['Declared files'] = count;
  const sparse = Boolean(flags & 4);
  if (flags & 1 || flags & ~7) {
    report.warnings.push('The PCK directory uses encryption or unsupported flags.');
    return;
  }
  if (sparse) report.warnings.push('Sparse PCK entries may reference external files. Only directory metadata is shown.');
  const afterCount = start + 4;
  const hardEnd = !directoryAtEnd && modern && base >= BigInt(afterCount) && base <= BigInt(blob.size) ?
    Number(base) : blob.size;
  const limit = Math.min(hardEnd, afterCount + maxDirectory);
  const bytes = new Uint8Array(await blob.slice(afterCount, limit).arrayBuffer());
  const data = view(bytes);
  const tail = modern ? 36 : 32;
  const entries = [];
  const directoryRow = { name: 'Directory', kind: 'PCK directory', offset: start, size: 4 };
  report.rows.push(directoryRow);
  let at = 0;
  let limited = false;
  try {
    for (let i = 0; i < Math.min(count, maxEntries); i++) {
      if (at + 4 > bytes.length) {
        if (limit === hardEnd) throw new Error('Truncated PCK path record.');
        limited = true;
        break;
      }
      const width = data.getUint32(at, true);
      const meta = at + 4 + width;
      if (!width || width > 8192) throw new Error('Invalid PCK path length.');
      if (meta + tail > bytes.length) {
        if (limit === hardEnd) throw new Error('Truncated PCK directory record.');
        limited = true;
        break;
      }
      const path = bytes.subarray(at + 4, meta);
      const zero = path.indexOf(0);
      if (zero >= 0 && path.subarray(zero).some(byte => byte !== 0)) throw new Error('Invalid PCK path padding.');
      const name = decoder.decode(zero >= 0 ? path.subarray(0, zero) : path);
      if (!name) throw new Error('Empty PCK entry path.');
      const relative = data.getBigUint64(meta, true);
      const size = data.getBigUint64(meta + 8, true);
      const hash = byteHex(bytes.subarray(meta + 16, meta + 32));
      const entryFlags = modern ? data.getUint32(meta + 32, true) : 0;
      entries.push({ name, relative, size, hash, flags: entryFlags, recordOffset: afterCount + at, recordSize: 4 + width + tail });
      at = meta + tail;
    }
  } catch (error) {
    report.status = 'partial';
    report.warnings.push(error.message);
  }
  if (limited) report.warnings.push('The PCK directory reached the 24 MiB read limit.');
  directoryRow.size += at;
  if (count > maxEntries) report.warnings.push('The PCK file list is limited to 20,000 entries.');
  const lower = BigInt(directoryAtEnd ? headerSize : afterCount + at);
  const upper = directoryAtEnd ? directory : BigInt(blob.size);
  let invalid = 0;
  let duplicates = 0;
  const seen = new Set();
  for (const entry of entries) {
    const { name, relative, size, hash, flags, recordOffset, recordSize } = entry;
    const normalized = name.replace(/^res:\/\//, '');
    if (seen.has(normalized)) duplicates++;
    seen.add(normalized);
    const kind = flags & 2 ? 'PCK removal' : flags & 1 ? 'PCK encrypted file' :
      flags & 4 ? 'PCK delta file' : flags & ~7 ? 'PCK file with unsupported flags' : 'PCK file';
    const target = base + relative;
    const safe = target >= lower && target <= upper && size <= upper - target;
    const ordinary = kind === 'PCK file' && !sparse;
    const usable = ordinary && safe && (directoryAtEnd || entries.length === count || (modern && base === BigInt(hardEnd)));
    if (ordinary && !safe) invalid++;
    report.rows.push({
      name, kind, offset: usable ? Number(target) : null, size: size <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(size) : null,
      recordOffset, recordSize, declaredMd5: hash, flags, open: usable,
      ...(!usable ? { note: ordinary && !safe ? 'Payload range is outside the pack data.' : 'Directory metadata only.' } : {})
    });
  }
  if (invalid) report.warnings.push(invalid + ' PCK entries have payload ranges outside the pack data.');
  if (duplicates) report.warnings.push(duplicates + ' PCK entries reuse a path.');
}

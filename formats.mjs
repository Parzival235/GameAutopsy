import { inspectPck } from './pck.mjs';
import { inspectAxml } from './axml.mjs?v=0.12.0';
import { inspectSerializedFile, looksLikeSerializedFile } from './unity-serialized.mjs?v=0.12.0';

import { decodeUnityLzma, maxLzmaBlock } from './unity-lzma.mjs?v=0.12.0';

export { sampleStrings } from './string-scan.mjs?v=0.12.0';

export const version = '0.12.0';
export const MiB = 1024 * 1024;
const maxRows = 20000;
const maxDirectory = 24 * MiB;
const utf8 = new TextDecoder();
const legacyZip = 'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ';

function requireRange(size, offset, length) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) ||
      offset < 0 || length < 0 || offset > size || length > size - offset) {
    throw new Error('Data range is outside the file or exceeds the safe integer range.');
  }
}

export async function bytesAt(blob, offset, length) {
  requireRange(blob.size, offset, length);
  return new Uint8Array(await blob.slice(offset, offset + length).arrayBuffer());
}

function view(bytes) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function u64(d, offset, little = true) {
  const value = d.getBigUint64(offset, little);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('64-bit value exceeds the safe integer range.');
  return Number(value);
}

const ascii = bytes => new TextDecoder('ascii').decode(bytes);
const hex = (n, width = 0) => '0x' + n.toString(16).toUpperCase().padStart(width, '0');
const starts = (bytes, signature) => signature.every((v, i) => bytes[i] === v);
const zipMagic = b => starts(b, [80, 75, 3, 4]) || starts(b, [80, 75, 5, 6]) || starts(b, [80, 75, 7, 8]);
const row = (name, kind, offset, size, extra = {}) => ({ name, kind, offset, size, ...extra });

export function identify(bytes, name = '', size = bytes.length) {
  const text = ascii(bytes.subarray(0, 8));
  if (zipMagic(bytes)) return 'ZIP';
  if (starts(bytes, [127, 69, 76, 70])) return 'ELF';
  if (text.startsWith('MZ')) return 'PE';
  if (text.startsWith('dex\n')) return 'DEX';
  if (text === 'UnityFS\0') return 'UnityFS';
  if (text.startsWith('UnityWeb') || text.startsWith('UnityRaw')) return 'Unity legacy';
  if (text.startsWith('GDPC')) return 'Godot PCK';
  if (starts(bytes, [175, 27, 177, 250])) return 'IL2CPP metadata';
  if (starts(bytes, [3, 0, 8, 0])) return 'Android binary XML';
  if (starts(bytes, [0x89, 80, 78, 71, 13, 10, 26, 10])) return 'PNG';
  if (text.startsWith('RIFF')) return 'RIFF';
  if (text.startsWith('OggS')) return 'Ogg';
  if (starts(bytes, [255, 216, 255])) return 'JPEG';
  if (starts(bytes, [31, 139])) return 'GZIP';
  if (starts(bytes, [55, 122, 188, 175, 39, 28])) return '7z';
  if (starts(bytes, [0, 97, 115, 109])) return 'WebAssembly';
  if (looksLikeSerializedFile(bytes, name, size)) return 'Unity serialized file';
  return /\.(zip|apk|apks|xapk|aab|ipa)$/i.test(name) ? 'ZIP' : 'Binary';
}

function extras(bytes, needs) {
  const d = view(bytes);
  for (let i = 0; i + 4 <= bytes.length;) {
    const tag = d.getUint16(i, true);
    const length = d.getUint16(i + 2, true);
    const end = i + 4 + length;
    if (end > bytes.length) break;
    if (tag === 1) {
      const values = {};
      let next = i + 4;
      for (const [key, width] of needs) {
        if (next + width > end) throw new Error('Truncated ZIP64 extra field.');
        values[key] = width === 8 ? u64(d, next) : d.getUint32(next, true);
        next += width;
      }
      return values;
    }
    i = end;
  }
  if (needs.length) throw new Error('Missing ZIP64 extra field.');
  return {};
}

const zipName = (bytes, flags) => flags & 0x800 ? utf8.decode(bytes) :
  Array.from(bytes, n => n < 128 ? String.fromCharCode(n) : legacyZip[n - 128]).join('');

async function zipDirectory(blob) {
  const tailOffset = Math.max(0, blob.size - 65557);
  const tail = view(await bytesAt(blob, tailOffset, blob.size - tailOffset));
  let at = tail.byteLength - 22;
  for (; at >= 0; at--) {
    if (tail.getUint32(at, true) === 0x06054b50 &&
        at + 22 + tail.getUint16(at + 20, true) === tail.byteLength) break;
  }
  if (at < 0) throw new Error('ZIP end of central directory (EOCD) was not found.');
  if (tail.getUint16(at + 4, true) || tail.getUint16(at + 6, true)) {
    throw new Error('Multi-disk ZIP archives are unsupported.');
  }
  let count = tail.getUint16(at + 10, true);
  if (tail.getUint16(at + 8, true) !== count) throw new Error('Multi-disk ZIP archives are unsupported.');
  let length = tail.getUint32(at + 12, true);
  let offset = tail.getUint32(at + 16, true);
  const eocd = tailOffset + at;
  let boundary = eocd;
  let zip64 = false;
  if (count === 65535 || length === 0xffffffff || offset === 0xffffffff) {
    const locator = eocd >= 20 ? view(await bytesAt(blob, eocd - 20, 20)) : null;
    if (locator?.getUint32(0, true) === 0x07064b50) {
      if (locator.getUint32(4, true) || locator.getUint32(16, true) !== 1) {
        throw new Error('Multi-disk ZIP64 archives are unsupported.');
      }
      boundary = u64(locator, 8);
      if (boundary > eocd - 76) throw new Error('ZIP64 EOCD is outside the expected range.');
      const record = view(await bytesAt(blob, boundary, 56));
      if (record.getUint32(0, true) !== 0x06064b50 || u64(record, 4) !== eocd - 32 - boundary) {
        throw new Error('Invalid ZIP64 EOCD structure.');
      }
      if (record.getUint32(16, true) || record.getUint32(20, true) ||
          u64(record, 24) !== u64(record, 32)) throw new Error('Multi-disk ZIP64 archives are unsupported.');
      count = u64(record, 32);
      length = u64(record, 40);
      offset = u64(record, 48);
      zip64 = true;
    } else if (length === 0xffffffff || offset === 0xffffffff) {
      throw new Error('Missing ZIP64 locator.');
    }
  }
  requireRange(boundary, offset, length);
  return { count, length, offset, eocd, zip64 };
}

async function parseZip(blob, out, progress) {
  const { count, length, offset, eocd, zip64 } = await zipDirectory(blob);
  Object.assign(out.details, { 'Declared entries': count, 'Central directory': hex(offset), 'Directory size': length, EOCD: hex(eocd), ZIP64: zip64 ? 'Yes' : 'No' });
  progress({ stage: 'Reading ZIP central directory' });
  const data = await bytesAt(blob, offset, Math.min(length, maxDirectory));
  const d = view(data);
  let pos = 0;
  const total = Math.min(count, maxRows);
  progress({ stage: 'Parsing ZIP entries', done: 0, total, unit: 'entries' });
  while (out.rows.length < count && out.rows.length < maxRows) {
    if (pos + 46 > data.length) break;
    if (d.getUint32(pos, true) !== 0x02014b50) throw new Error('Invalid central directory entry signature.');
    const nameLength = d.getUint16(pos + 28, true);
    const extraLength = d.getUint16(pos + 30, true);
    const end = pos + 46 + nameLength + extraLength + d.getUint16(pos + 32, true);
    if (end > data.length) break;
    const flags = d.getUint16(pos + 8, true);
    const method = d.getUint16(pos + 10, true);
    const rawName = data.subarray(pos + 46, pos + 46 + nameLength);
    const name = zipName(rawName, flags);
    let size = d.getUint32(pos + 24, true);
    let packed = d.getUint32(pos + 20, true);
    let local = d.getUint32(pos + 42, true);
    let disk = d.getUint16(pos + 34, true);
    const needs = [];
    if (size === 0xffffffff) needs.push(['size', 8]);
    if (packed === 0xffffffff) needs.push(['packed', 8]);
    if (local === 0xffffffff) needs.push(['local', 8]);
    if (disk === 65535) needs.push(['disk', 4]);
    const extra = extras(data.subarray(pos + 46 + nameLength, pos + 46 + nameLength + extraLength), needs);
    ({ size = size, packed = packed, local = local, disk = disk } = extra);
    const folder = name.endsWith('/');
    const encrypted = Boolean(flags & 0x2041);
    out.rows.push(row(name, folder ? 'Directory' : encrypted ? 'Encrypted' : method === 0 ? 'Stored' : method === 8 ? 'Deflate' : 'Method ' + method, local, size, {
      packed, crc32: d.getUint32(pos + 16, true), central: offset + pos, directoryOffset: offset, flags, method,
      open: !folder && !encrypted && disk === 0 && (method === 0 || method === 8)
    }));
    pos = end;
    if (out.rows.length % 256 === 0) progress({ stage: 'Parsing ZIP entries', done: out.rows.length, total, unit: 'entries' });
  }
  progress({ stage: 'Parsing ZIP entries', done: out.rows.length, total, unit: 'entries' });
  if (out.rows.length !== count) {
    if (out.rows.length === maxRows || length > maxDirectory) {
      out.warnings.push('The directory exceeds 20,000 entries or 24 MiB. The report contains the entries read so far.');
    } else {
      throw new Error('The central directory is truncated or its entry count is incorrect.');
    }
  }
}

const crcTable = Uint32Array.from({ length: 256 }, (_, i) => {
  for (let j = 0; j < 8; j++) i = i & 1 ? 0xedb88320 ^ (i >>> 1) : i >>> 1;
  return i;
});

async function crcOf(blob, progress) {
  let crc = -1;
  let done = 0;
  let nextUpdate = 0;
  const update = () => progress({ stage: 'Checking entry CRC32', done, total: blob.size, unit: 'bytes' });
  update();
  for await (const chunk of blob.stream()) {
    for (const byte of chunk) crc = crcTable[(crc ^ byte) & 255] ^ (crc >>> 8);
    done += chunk.length;
    if (done >= nextUpdate + 4 * MiB) {
      update();
      nextUpdate = done;
    }
  }
  update();
  return (crc ^ -1) >>> 0;
}

export async function openZipMember(blob, entry, progress = () => {}) {
  if (!entry.open) throw new Error('This entry cannot be opened in the browser.');
  if (entry.size > 128 * MiB || entry.packed > 128 * MiB) {
    throw new Error('The entry exceeds the 128 MiB open limit.');
  }
  const start = await zipLocalInfo(blob, entry);
  const packed = blob.slice(start, start + entry.packed);
  let content = packed;
  if (entry.method === 8) {
    const reader = packed.stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader();
    const parts = [];
    let size = 0;
    let nextUpdate = 0;
    const update = () => progress({ stage: 'Inflating ZIP entry', done: size, total: entry.size, unit: 'bytes' });
    update();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > entry.size) throw new Error('Decompressed data exceeds the declared size.');
        parts.push(value);
        if (size >= nextUpdate + 4 * MiB) {
          update();
          nextUpdate = size;
        }
      }
    } catch (error) {
      await reader.cancel().catch(() => {});
      throw error;
    } finally {
      reader.releaseLock();
    }
    update();
    content = new Blob(parts);
  }
  if (content.size !== entry.size || await crcOf(content, progress) !== entry.crc32) {
    throw new Error('The entry size or CRC32 does not match.');
  }
  return { blob: content, dataOffset: start };
}

export async function zipLocalInfo(blob, entry, boundary = entry.directoryOffset) {
  requireRange(boundary, entry.offset, 30);
  const h = view(await bytesAt(blob, entry.offset, 30));
  if (h.getUint32(0, true) !== 0x04034b50 ||
      h.getUint16(6, true) !== entry.flags || h.getUint16(8, true) !== entry.method) {
    throw new Error('The local header and central directory disagree.');
  }
  const centralHeader = view(await bytesAt(blob, entry.central, 46));
  const nameLength = h.getUint16(26, true);
  if (nameLength !== centralHeader.getUint16(28, true)) throw new Error('The filenames in the two ZIP headers disagree.');
  const start = entry.offset + 30 + nameLength + h.getUint16(28, true);
  requireRange(boundary, start, entry.packed);
  const local = await bytesAt(blob, entry.offset + 30, nameLength + h.getUint16(28, true));
  const centralName = await bytesAt(blob, entry.central + 46, nameLength);
  if (!centralName.every((byte, i) => byte === local[i])) throw new Error('The filenames in the two ZIP headers disagree.');
  if (!(entry.flags & 8)) {
    let packed = h.getUint32(18, true);
    let size = h.getUint32(22, true);
    const needs = [];
    if (size === 0xffffffff) needs.push(['size', 8]);
    if (packed === 0xffffffff) needs.push(['packed', 8]);
    ({ size = size, packed = packed } = extras(local.subarray(nameLength), needs));
    if (packed !== entry.packed || size !== entry.size || h.getUint32(14, true) !== entry.crc32) {
      throw new Error('The ZIP headers disagree on size or CRC32.');
    }
  }
  if (entry.method === 0 && !(entry.flags & 0x2041) && entry.packed !== entry.size) {
    throw new Error('Stored ZIP entry has inconsistent sizes.');
  }
  return start;
}

async function parseDex(blob, out) {
  let headerOffset = 0;
  let containerEnd;
  let headerCount = 0;
  for (;;) {
    const bytes = await bytesAt(blob, headerOffset, 112);
    const d = view(bytes);
    const endian = d.getUint32(40, true);
    if (![0x12345678, 0x78563412].includes(endian)) throw new Error('Invalid DEX endian tag.');
    const little = endian === 0x12345678;
    const read = i => d.getUint32(i, little);
    const dexVersion = ascii(bytes.subarray(4, 7));
    const declared = read(32);
    const headerSize = read(36);
    const container = dexVersion === '041';
    if (ascii(bytes.subarray(0, 4)) !== 'dex\n' || !/^\d{3}$/.test(dexVersion) ||
        bytes[7] || headerSize < 112 || headerSize > declared ||
        (headerOffset && !container)) throw new Error('Invalid DEX header.');
    if (Number(dexVersion) > 41) {
      out.warnings.push('This DEX version is newer than the versions supported by the structure reader.');
      return;
    }
    if (headerSize !== (container ? 120 : 112)) throw new Error('Invalid DEX header size.');
    if (container) {
      const extra = view(await bytesAt(blob, headerOffset + 112, 8));
      const end = extra.getUint32(0, little);
      if (extra.getUint32(4, little) !== headerOffset || end !== (containerEnd ?? blob.size)) {
        throw new Error('Inconsistent DEX container size or header offset.');
      }
      containerEnd = end;
    } else {
      containerEnd = declared;
    }
    requireRange(Math.min(containerEnd, blob.size), headerOffset, declared);
    if (!headerCount) {
      Object.assign(out.details, {
        'DEX version': dexVersion, [container ? 'Container size' : 'Declared size']: containerEnd,
        Endian: little ? 'Little' : 'Big', 'Declared Adler-32': hex(read(8), 8)
      });
    }
    const logicalIndex = container ? headerCount : null;
    out.rows.push(row('header', 'DEX', headerOffset, headerSize, container ? {
      logicalIndex, logicalSize: declared, declaredAdler32: hex(read(8), 8)
    } : {}));
    await dexTables(blob, out, read, little, headerOffset, containerEnd, logicalIndex);
    headerCount++;
    if (container) out.details['Logical DEX files read'] = headerCount;
    if (!container || headerOffset + declared === containerEnd) return;
    if (headerCount === 64 || out.rows.length >= maxRows) {
      out.warnings.push('DEX output reached its logical file or structure limit.');
      return;
    }
    headerOffset += declared;
  }
}

async function dexTables(blob, out, read, little, start, end, logicalIndex) {
  const tables = [
    ['link data', 44, 1], ['string IDs', 56, 4], ['type IDs', 64, 4],
    ['proto IDs', 72, 12], ['field IDs', 80, 8], ['method IDs', 88, 8],
    ['class defs', 96, 32]
  ];
  if (logicalIndex === null) tables.push(['data', 104, 1]);
  const logical = logicalIndex === null ? {} : { logicalIndex };
  for (const [name, at, width] of tables) {
    const count = read(at);
    const offset = read(at + 4);
    if (!count) continue;
    if (out.rows.length >= maxRows) {
      out.warnings.push('DEX table output is limited to 20,000 structure rows.');
      return;
    }
    requireRange(end - start, offset - start, count * width);
    out.rows.push(row(name, 'DEX table', offset, count * width, { count, ...logical }));
  }
  const map = read(52);
  if (!map) return;
  requireRange(end - start, map - start, 4);
  const count = view(await bytesAt(blob, map, 4)).getUint32(0, little);
  if (count > 4096) throw new Error('The DEX map has too many entries.');
  requireRange(end - start, map - start, 4 + count * 12);
  const items = view(await bytesAt(blob, map + 4, count * 12));
  const kinds = { 0: 'header', 1: 'string IDs', 2: 'type IDs', 3: 'proto IDs', 4: 'field IDs', 5: 'method IDs', 6: 'class defs', 7: 'call site IDs', 8: 'method handles', 0x1000: 'map list', 0x1001: 'type lists', 0x1002: 'annotation set refs', 0x1003: 'annotation sets', 0x2000: 'class data', 0x2001: 'code items', 0x2002: 'string data', 0x2003: 'debug info', 0x2004: 'annotations', 0x2005: 'encoded arrays', 0x2006: 'annotation directories', 0xf000: 'hidden API data' };
  for (let i = 0; i < count * 12; i += 12) {
    if (out.rows.length >= maxRows) {
      out.warnings.push('DEX map output is limited to 20,000 structure rows.');
      break;
    }
    const type = items.getUint16(i, little);
    const offset = items.getUint32(i + 8, little);
    requireRange(end - start, offset - start, 1);
    out.rows.push(row(kinds[type] || 'type ' + hex(type, 4), 'DEX map', offset, null, {
      count: items.getUint32(i + 4, little), ...logical
    }));
  }
}

function cstr(bytes, start, limit = bytes.length) {
  if (start >= bytes.length) return '';
  const window = bytes.subarray(start, start + limit);
  const end = window.indexOf(0);
  return utf8.decode(end < 0 ? window : window.subarray(0, end));
}

async function parseElf(blob, out, head) {
  if (![1, 2].includes(head[4]) || ![1, 2].includes(head[5]) || head[6] !== 1) {
    throw new Error('Invalid ELF class, endianness or version.');
  }
  const wide = head[4] === 2;
  const little = head[5] === 1;
  const d = view(await bytesAt(blob, 0, wide ? 64 : 52));
  const short = i => d.getUint16(i, little);
  const word = i => wide ? u64(d, i, little) : d.getUint32(i, little);
  const address = i => hex(wide ? d.getBigUint64(i, little) : d.getUint32(i, little));
  const phoff = word(wide ? 32 : 28);
  const shoff = word(wide ? 40 : 32);
  const phSize = short(wide ? 54 : 42);
  const shSize = short(wide ? 58 : 46);
  let phCount = short(wide ? 56 : 44);
  let shCount = short(wide ? 60 : 48);
  let namesIndex = short(wide ? 62 : 50);
  const machine = short(18);
  const arch = { 3: 'x86', 8: 'MIPS', 20: 'PowerPC', 21: 'PowerPC64', 40: 'ARM', 62: 'x86-64', 183: 'AArch64', 243: 'RISC-V' };
  if (shoff && (!shCount || phCount === 65535 || namesIndex === 65535)) {
    const first = view(await bytesAt(blob, shoff, wide ? 64 : 40));
    if (!shCount) shCount = wide ? u64(first, 32, little) : first.getUint32(20, little);
    if (phCount === 65535) phCount = first.getUint32(wide ? 44 : 28, little);
    if (namesIndex === 65535) namesIndex = first.getUint32(wide ? 40 : 24, little);
  }
  Object.assign(out.details, { 'Architecture': arch[machine] || hex(machine), Bit: wide ? 64 : 32, Endian: little ? 'Little' : 'Big', 'Entry VA': address(24), Segment: phCount, Section: shCount });
  const table = async (offset, size, count, minimum) => {
    if (!count) return new DataView(new ArrayBuffer(0));
    if (size < minimum) throw new Error('Invalid ELF record size.');
    requireRange(blob.size, offset, count * size);
    const limit = Math.min(maxRows, Math.floor(maxDirectory / size));
    if (count > limit) out.warnings.push('An ELF table exceeded the display limit and was truncated.');
    return view(await bytesAt(blob, offset, Math.min(count, limit) * size));
  };
  const ph = await table(phoff, phSize, phCount, wide ? 56 : 32);
  const sh = await table(shoff, shSize, shCount, wide ? 64 : 40);
  const field = (t, i) => wide ? u64(t, i, little) : t.getUint32(i, little);
  const va = (t, i) => hex(wide ? t.getBigUint64(i, little) : t.getUint32(i, little));
  let loadCount = 0;
  let unaligned = 0;
  let invalid = 0;
  for (let i = 0; i < ph.byteLength; i += phSize) {
    const type = ph.getUint32(i, little);
    const offset = field(ph, i + (wide ? 8 : 4));
    const fileSize = field(ph, i + (wide ? 32 : 16));
    const memorySize = field(ph, i + (wide ? 40 : 20));
    const addr = BigInt(va(ph, i + (wide ? 16 : 8)));
    const align = BigInt(va(ph, i + (wide ? 48 : 28)));
    const flags = ph.getUint32(i + (wide ? 4 : 24), little);
    const permissions = (flags & 4 ? 'R' : '-') + (flags & 2 ? 'W' : '-') + (flags & 1 ? 'X' : '-');
    let note = permissions + ' · Align ' + hex(align);
    if (type === 1) {
      loadCount++;
      const valid = (align === 0n || (align & (align - 1n)) === 0n) &&
        (align < 2n || addr % align === BigInt(offset) % align) &&
        fileSize <= memorySize && (!fileSize || (offset <= blob.size && fileSize <= blob.size - offset));
      if (!valid) {
        invalid++;
        note += ' · Invalid LOAD layout';
      } else if (align < 16384n) {
        unaligned++;
        note += ' · Below 16 KiB';
      }
    }
    out.rows.push(row('Segment ' + i / phSize, type === 1 ? 'PT_LOAD' : 'PT ' + hex(type), offset, fileSize, {
      address: hex(addr), alignment: hex(align), memorySize, flags, note
    }));
  }
  if (loadCount) {
    const checkedAll = ph.byteLength / phSize === phCount;
    out.details['LOAD segments inspected'] = loadCount;
    out.details['ELF LOAD 16 KiB alignment'] = invalid ? 'Invalid LOAD layout' :
      unaligned ? unaligned + ' below 16 KiB' : checkedAll ? 'All inspected LOAD segments aligned' : 'Partial program header table';
    if (invalid) out.warnings.push('One or more ELF LOAD segments have invalid ranges or alignment.');
  }
  const nameAt = namesIndex * shSize;
  let names = new Uint8Array();
  if (namesIndex && nameAt + shSize <= sh.byteLength) {
    const size = field(sh, nameAt + (wide ? 32 : 20));
    if (size <= maxDirectory) names = await bytesAt(blob, field(sh, nameAt + (wide ? 24 : 16)), size);
    else out.warnings.push('The section name table exceeds 24 MiB.');
  }
  for (let i = 0; i < sh.byteLength && out.rows.length < maxRows; i += shSize) {
    const type = sh.getUint32(i + 4, little);
    const name = cstr(names, sh.getUint32(i, little), 4096) || 'Section ' + i / shSize;
    const size = field(sh, i + (wide ? 32 : 20));
    out.rows.push(row(name, 'SHT ' + hex(type), type === 8 ? null : field(sh, i + (wide ? 24 : 16)), size, { address: va(sh, i + (wide ? 16 : 12)) }));
  }
  if (phCount + shCount > maxRows) out.warnings.push('Structure output is limited to 20,000 rows.');
}

async function parsePe(blob, out, head) {
  if (head.length < 64) throw new Error('Missing DOS header.');
  const at = view(head).getUint32(60, true);
  const d = view(await bytesAt(blob, at, 24));
  if (d.getUint32(0, true) !== 0x4550) throw new Error('PE signature was not found.');
  const count = d.getUint16(6, true);
  const optSize = d.getUint16(20, true);
  const opt = view(await bytesAt(blob, at + 24, optSize));
  const magic = optSize >= 2 ? opt.getUint16(0, true) : 0;
  const wide = magic === 0x20b;
  const dirStart = wide ? 112 : 96;
  if ((!wide && magic !== 0x10b) || optSize < dirStart) throw new Error('The PE optional header is unsupported or truncated.');
  const machine = d.getUint16(4, true);
  const arch = { 332: 'x86', 34404: 'x86-64', 452: 'ARM', 43620: 'ARM64' };
  Object.assign(out.details, { 'Architecture': arch[machine] || hex(machine), 'Optional header': wide ? 'PE32+' : 'PE32', 'Entry RVA': hex(opt.getUint32(16, true)), 'Image base': hex(wide ? opt.getBigUint64(24, true) : opt.getUint32(28, true)), Section: count });
  if (count > maxRows) throw new Error('The PE section count exceeds the limit.');
  out.rows.push(row('PE headers', 'PE', at, 24 + optSize + count * 40));
  const table = await bytesAt(blob, at + 24 + optSize, count * 40);
  const s = view(table);
  const sections = [];
  for (let i = 0; i < count * 40; i += 40) {
    const name = cstr(table.subarray(i, i + 8), 0) || '(section)';
    const va = s.getUint32(i + 12, true);
    const size = s.getUint32(i + 16, true);
    const offset = s.getUint32(i + 20, true);
    sections.push({ va, size, offset });
    out.rows.push(row(name, 'Section', size ? offset : null, size, { address: hex(va), virtualSize: s.getUint32(i + 8, true) }));
  }
  const dirs = ['Export', 'Import', 'Resource', 'Exception', 'Certificate', 'Relocation', 'Debug', 'Architecture', 'Global ptr', 'TLS', 'Load config', 'Bound import', 'IAT', 'Delay import', 'CLR', 'Reserved'];
  const declared = opt.getUint32(dirStart - 4, true);
  const available = Math.floor((optSize - dirStart) / 8);
  if (declared > available) out.warnings.push('The declared data directory count exceeds the optional header size.');
  for (let i = 0; i < Math.min(declared, available, dirs.length); i++) {
    const address = opt.getUint32(dirStart + i * 8, true);
    const size = opt.getUint32(dirStart + i * 8 + 4, true);
    if (!address) continue;
    const section = sections.find(s => address >= s.va && address < s.va + s.size && size <= s.va + s.size - address);
    const offset = i === 4 ? address : section ? section.offset + address - section.va : null;
    out.rows.push(row(dirs[i], 'Data directory', offset, size, i === 4 ? {} : { address: hex(address) }));
  }
}

const unityCompression = ['Raw', 'LZMA', 'LZ4', 'LZ4HC', 'LZHAM'];
const align16 = n => Math.ceil(n / 16) * 16;

function decodeLz4(input, size) {
  const output = new Uint8Array(size);
  let read = 0;
  let written = 0;
  const length = initial => {
    if (initial !== 15) return initial;
    let total = initial;
    let next;
    do {
      if (read === input.length) throw new Error('Truncated LZ4 length.');
      next = input[read++];
      total += next;
    } while (next === 255);
    return total;
  };
  while (read < input.length) {
    const token = input[read++];
    const literal = length(token >> 4);
    if (literal > input.length - read || literal > size - written) throw new Error('Invalid LZ4 literal range.');
    output.set(input.subarray(read, read + literal), written);
    read += literal;
    written += literal;
    if (read === input.length) {
      if (written === size) return output;
      break;
    }
    if (input.length - read < 2) throw new Error('Truncated LZ4 match offset.');
    const distance = input[read] | (input[read + 1] << 8);
    read += 2;
    const match = length(token & 15) + 4;
    if (!distance || distance > written || match > size - written) throw new Error('Invalid LZ4 match range.');
    for (let i = 0; i < match; i++, written++) output[written] = output[written - distance];
  }
  throw new Error('LZ4 output does not match the declared size.');
}

async function parseUnity(blob, out, head) {
  const first = head.indexOf(0, 12);
  const second = head.indexOf(0, first + 1);
  if (first < 12 || second < 0 || second + 21 > head.length) {
    throw new Error('The UnityFS header is truncated or exceeds 512 bytes.');
  }
  const d = view(head);
  const version = d.getUint32(8);
  const size = u64(d, second + 1, false);
  const packed = d.getUint32(second + 9);
  const unpacked = d.getUint32(second + 13);
  const flags = d.getUint32(second + 17);
  const engine = cstr(head, first + 1);
  const engineVersion = /^(\d+)\.(\d+)\.(\d+)/.exec(engine)?.slice(1).map(Number);
  const [major, minor, patch] = engineVersion ?? [];
  const oldFlags = major < 2020 || (major === 2020 && (minor < 3 || (minor === 3 && patch < 34))) ||
    (major === 2021 && (minor < 3 || (minor === 3 && patch < 2))) ||
    (major === 2022 && (minor < 1 || (minor === 1 && patch < 1)));
  const end = second + 21;
  const headSize = version >= 7 || (major === 2019 && (minor > 4 || (minor === 4 && patch >= 15))) ? align16(end) : end;
  requireRange(blob.size, 0, size);
  requireRange(size, 0, headSize);
  const fromEnd = Boolean(flags & 0x80);
  const method = flags & 0x3f;
  Object.assign(out.details, {
    'Format version': version, 'Player version': cstr(head, 12), 'Engine version': engine,
    'Declared size': size, 'Decoded directory size': unpacked, 'Directory compression': unityCompression[method] ?? method,
    Flags: hex(flags)
  });
  out.rows.push(row('Header', 'UnityFS', 0, headSize));
  if (version < 6 || version > 8 || !(flags & 0x40) || flags & (oldFlags ? 0x200 : 0x1400) ||
      (!engineVersion && flags & 0x200)) {
    out.warnings.push('The UnityFS directory layout or flags are unsupported. Only the header was read.');
    return;
  }
  const directory = fromEnd ? size - packed : headSize;
  requireRange(size, directory, packed);
  if (directory < headSize) throw new Error('The UnityFS directory overlaps the header.');
  out.rows.push(row('Blocks info', 'UnityFS directory', directory, packed));
  if (![0, 1, 2, 3].includes(method) || Math.max(packed, unpacked) > maxDirectory) {
    out.warnings.push('The UnityFS directory uses an unsupported compression method or exceeds 24 MiB.');
    return;
  }
  const payload = await bytesAt(blob, directory, packed);
  const table = method === 1 ? decodeUnityLzma(payload, unpacked) : method ? decodeLz4(payload, unpacked) : payload;
  if (table.length !== unpacked) throw new Error('The UnityFS directory size does not match the header.');
  let dataStart = fromEnd ? headSize : directory + packed;
  if (!oldFlags && flags & 0x200) dataStart = align16(dataStart);
  listUnityBlocks(table, dataStart, fromEnd ? directory : size, out);
}

function listUnityBlocks(bytes, dataStart, dataEnd, out) {
  const d = view(bytes);
  requireRange(bytes.length, 0, 20);
  const blocks = d.getUint32(16);
  requireRange(bytes.length, 20, blocks * 10 + 4);
  if (blocks > maxRows - out.rows.length) {
    out.warnings.push('The UnityFS block count exceeds the structure limit.');
    return;
  }
  let streamSize = 0;
  let offset = dataStart;
  let i = 20;
  for (let block = 0; block < blocks; block++, i += 10) {
    const decoded = d.getUint32(i);
    const packed = d.getUint32(i + 4);
    const flags = d.getUint16(i + 8);
    requireRange(dataEnd, offset, packed);
    out.rows.push(row('Block ' + block, 'UnityFS block', offset, packed, {
      streamOffset: streamSize, unpackedSize: decoded, flags,
      note: (unityCompression[flags & 0x3f] ?? 'Unknown compression') + ' · ' + decoded + ' decoded bytes'
    }));
    offset += packed;
    streamSize += decoded;
  }
  const entries = d.getUint32(i);
  Object.assign(out.details, { 'Declared blocks': blocks, 'Declared files': entries, 'Decoded stream size': streamSize });
  i += 4;
  for (let entry = 0; entry < entries; entry++) {
    if (out.rows.length === maxRows) {
      out.warnings.push('The UnityFS file list reached the structure limit.');
      return;
    }
    requireRange(bytes.length, i, 21);
    const streamOffset = u64(d, i, false);
    const size = u64(d, i + 8, false);
    const flags = d.getUint32(i + 16);
    const end = bytes.indexOf(0, i + 20);
    if (end < 0 || end - i - 20 > 4096) throw new Error('Invalid UnityFS file name.');
    requireRange(streamSize, streamOffset, size);
    const name = utf8.decode(bytes.subarray(i + 20, end));
    out.rows.push(row(name, 'UnityFS file', null, size, { streamOffset, flags, open: true }));
    i = end + 1;
  }
}

export async function openUnityMember(blob, report, entry) {
  if (entry.size > 128 * MiB) throw new Error('The UnityFS file exceeds the 128 MiB open limit.');
  const start = entry.streamOffset;
  const end = start + entry.size;
  const parts = [];
  let total = 0;
  for (const block of report.rows) {
    if (!entry.size) break;
    if (block.kind !== 'UnityFS block') continue;
    const next = block.streamOffset + block.unpackedSize;
    if (next <= start || block.streamOffset >= end) continue;
    const from = Math.max(start - block.streamOffset, 0);
    const to = Math.min(end - block.streamOffset, block.unpackedSize);
    const method = block.flags & 0x3f;
    let part;
    if (method === 0) {
      if (block.size !== block.unpackedSize) throw new Error(block.name + ' has inconsistent Raw sizes.');
      part = blob.slice(block.offset + from, block.offset + to);
    } else if ([1, 2, 3].includes(method)) {
      const compression = unityCompression[method];
      const limit = method === 1 ? maxLzmaBlock : 32 * MiB;
      if (Math.max(block.size, block.unpackedSize) > limit) {
        throw new Error(block.name + ' exceeds the 32 MiB ' + compression + ' block limit.');
      }
      const packed = await bytesAt(blob, block.offset, block.size);
      const decoded = method === 1 ? decodeUnityLzma(packed, block.unpackedSize) : decodeLz4(packed, block.unpackedSize);
      part = decoded.subarray(from, to);
    } else {
      throw new Error(block.name + ' uses unsupported compression (' + (unityCompression[method] ?? method) + ').');
    }
    total += to - from;
    parts.push(part instanceof Uint8Array ? new Blob([part]) : part);
  }
  if (total !== entry.size) throw new Error('The UnityFS blocks do not cover the entire file.');
  return new Blob(parts);
}

async function parseAndroidXml(blob, out, head) {
  if (head.length < 8) throw new Error('Missing XML header.');
  const d = view(head);
  const width = d.getUint16(2, true);
  const size = d.getUint32(4, true);
  if (width < 8 || width > size) throw new Error('Invalid XML header.');
  requireRange(blob.size, 0, size);
  out.details['Declared size'] = size;
  out.rows.push(row('XML header', 'AXML', 0, width));
  if (size > maxDirectory) {
    out.warnings.push('The XML exceeds 24 MiB. Only the header was read.');
    return;
  }
  inspectAxml(await bytesAt(blob, 0, size), out);
}


function entropy(bytes) {
  if (!bytes.length) return null;
  const counts = new Uint32Array(256);
  for (const byte of bytes) counts[byte]++;
  let result = 0;
  for (const count of counts) {
    if (count) {
      const p = count / bytes.length;
      result -= p * Math.log2(p);
    }
  }
  return Number(result.toFixed(3));
}

export async function analyze(blob, name, progress = () => {}) {
  progress({ stage: 'Reading file header' });
  const head = await bytesAt(blob, 0, Math.min(blob.size, 512));
  const format = identify(head, name, blob.size);
  const out = {
    schema: 'gameautopsy/1', version, name, format, size: blob.size, status: 'ok',
    details: {}, rows: [], warnings: []
  };
  const sample = Math.min(blob.size, 64 * 1024);
  if (sample) {
    progress({ stage: 'Sampling file entropy' });
    out.details['Head entropy (bits/byte)'] = entropy(await bytesAt(blob, 0, sample));
    out.details['Tail entropy (bits/byte)'] = entropy(await bytesAt(blob, blob.size - sample, sample));
    out.details['Entropy sample size'] = sample;
  }
  try {
    progress({ stage: 'Inspecting ' + format + ' structure' });
    switch (format) {
      case 'ZIP': await parseZip(blob, out, progress); break;
      case 'DEX': await parseDex(blob, out); break;
      case 'ELF': await parseElf(blob, out, head); break;
      case 'PE': await parsePe(blob, out, head); break;
      case 'UnityFS': await parseUnity(blob, out, head); break;
      case 'Unity serialized file': await inspectSerializedFile(blob, out, head, progress); break;
      case 'Android binary XML': await parseAndroidXml(blob, out, head); break;
      case 'Godot PCK': await inspectPck(blob, out, head); break;
      case 'IL2CPP metadata':
        if (head.length < 8) throw new Error('Missing IL2CPP header.');
        out.details['Metadata version'] = view(head).getUint32(4, true);
        break;
      default: break;
    }
  } catch (error) {
    out.status = 'partial';
    out.warnings.push(error.message);
  }
  return out;
}

export async function preview(blob, offset) {
  if (!blob.size && offset === 0) return { offset, bytes: [] };
  requireRange(blob.size, offset, 1);
  return { offset, bytes: [...await bytesAt(blob, offset, Math.min(256, blob.size - offset))] };
}

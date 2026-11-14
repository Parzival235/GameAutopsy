export const version = '0.1.0';
export const MiB = 1024 * 1024;
const maxRows = 20000;
const maxDirectory = 24 * MiB;
const utf8 = new TextDecoder();
const legacyZip = 'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ';

function requireRange(size, offset, length) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) ||
      offset < 0 || length < 0 || offset > size || length > size - offset) {
    throw new Error('Vùng dữ liệu nằm ngoài phạm vi file hoặc vượt giới hạn số nguyên.');
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
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Giá trị 64 bit vượt phạm vi an toàn.');
  return Number(value);
}

const ascii = bytes => new TextDecoder('ascii').decode(bytes);
const hex = (n, width = 0) => '0x' + n.toString(16).toUpperCase().padStart(width, '0');
const starts = (bytes, signature) => signature.every((v, i) => bytes[i] === v);
const zipMagic = b => starts(b, [80, 75, 3, 4]) || starts(b, [80, 75, 5, 6]) || starts(b, [80, 75, 7, 8]);
const row = (name, kind, offset, size, extra = {}) => ({ name, kind, offset, size, ...extra });

export function identify(bytes, name = '') {
  const text = ascii(bytes.subarray(0, 8));
  if (zipMagic(bytes) || /\.(zip|apk|apks|xapk|aab|ipa)$/i.test(name)) return 'ZIP';
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
  return 'Binary';
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
        if (next + width > end) throw new Error('ZIP64 extra field bị thiếu dữ liệu.');
        values[key] = width === 8 ? u64(d, next) : d.getUint32(next, true);
        next += width;
      }
      return values;
    }
    i = end;
  }
  if (needs.length) throw new Error('Thiếu ZIP64 extra field.');
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
  if (at < 0) throw new Error('Không tìm thấy bản ghi kết thúc ZIP (EOCD).');
  if (tail.getUint16(at + 4, true) || tail.getUint16(at + 6, true)) {
    throw new Error('ZIP chia nhiều đĩa chưa được hỗ trợ.');
  }
  let count = tail.getUint16(at + 10, true);
  if (tail.getUint16(at + 8, true) !== count) throw new Error('ZIP chia nhiều đĩa chưa được hỗ trợ.');
  let length = tail.getUint32(at + 12, true);
  let offset = tail.getUint32(at + 16, true);
  const eocd = tailOffset + at;
  let boundary = eocd;
  let zip64 = false;
  if (count === 65535 || length === 0xffffffff || offset === 0xffffffff) {
    const locator = eocd >= 20 ? view(await bytesAt(blob, eocd - 20, 20)) : null;
    if (locator?.getUint32(0, true) === 0x07064b50) {
      if (locator.getUint32(4, true) || locator.getUint32(16, true) !== 1) {
        throw new Error('ZIP64 chia nhiều đĩa chưa được hỗ trợ.');
      }
      boundary = u64(locator, 8);
      if (boundary > eocd - 76) throw new Error('ZIP64 EOCD nằm ngoài vùng hợp lệ.');
      const record = view(await bytesAt(blob, boundary, 56));
      if (record.getUint32(0, true) !== 0x06064b50 || u64(record, 4) !== eocd - 32 - boundary) {
        throw new Error('ZIP64 EOCD sai cấu trúc.');
      }
      if (record.getUint32(16, true) || record.getUint32(20, true) ||
          u64(record, 24) !== u64(record, 32)) throw new Error('ZIP64 chia nhiều đĩa chưa được hỗ trợ.');
      count = u64(record, 32);
      length = u64(record, 40);
      offset = u64(record, 48);
      zip64 = true;
    } else if (length === 0xffffffff || offset === 0xffffffff) {
      throw new Error('Thiếu ZIP64 locator.');
    }
  }
  requireRange(boundary, offset, length);
  return { count, length, offset, eocd, zip64 };
}

async function parseZip(blob, out) {
  const { count, length, offset, eocd, zip64 } = await zipDirectory(blob);
  Object.assign(out.details, { 'Số mục khai báo': count, 'Central directory': hex(offset), 'Kích thước danh mục': length, EOCD: hex(eocd), ZIP64: zip64 ? 'Có' : 'Không' });
  const data = await bytesAt(blob, offset, Math.min(length, maxDirectory));
  const d = view(data);
  let pos = 0;
  while (out.rows.length < count && out.rows.length < maxRows) {
    if (pos + 46 > data.length) break;
    if (d.getUint32(pos, true) !== 0x02014b50) throw new Error('Central directory có chữ ký mục không hợp lệ.');
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
    out.rows.push(row(name, folder ? 'Thư mục' : encrypted ? 'Mã hóa' : method === 0 ? 'Stored' : method === 8 ? 'Deflate' : 'Method ' + method, local, size, {
      packed, crc32: d.getUint32(pos + 16, true), central: offset + pos, flags, method,
      open: !folder && !encrypted && disk === 0 && (method === 0 || method === 8)
    }));
    pos = end;
  }
  if (out.rows.length !== count) {
    if (out.rows.length === maxRows || length > maxDirectory) {
      out.warnings.push('Danh mục vượt giới hạn 20.000 mục hoặc 24 MiB. Báo cáo chỉ chứa phần đã đọc.');
    } else {
      throw new Error('Central directory bị cắt ngắn hoặc sai số lượng mục.');
    }
  }
}

const crcTable = Uint32Array.from({ length: 256 }, (_, i) => {
  for (let j = 0; j < 8; j++) i = i & 1 ? 0xedb88320 ^ (i >>> 1) : i >>> 1;
  return i;
});

async function crcOf(blob) {
  let crc = -1;
  for await (const chunk of blob.stream()) {
    for (const byte of chunk) crc = crcTable[(crc ^ byte) & 255] ^ (crc >>> 8);
  }
  return (crc ^ -1) >>> 0;
}

export async function openZipMember(blob, entry) {
  if (!entry.open) throw new Error('Mục này không thể mở trong trình duyệt.');
  if (entry.size > 128 * MiB || entry.packed > 128 * MiB) {
    throw new Error('Mục vượt giới hạn mở 128 MiB.');
  }
  const h = view(await bytesAt(blob, entry.offset, 30));
  if (h.getUint32(0, true) !== 0x04034b50 ||
      h.getUint16(6, true) !== entry.flags || h.getUint16(8, true) !== entry.method) {
    throw new Error('Local header và central directory không khớp.');
  }
  const centralHeader = view(await bytesAt(blob, entry.central, 46));
  const nameLength = h.getUint16(26, true);
  if (nameLength !== centralHeader.getUint16(28, true)) throw new Error('Tên ở hai ZIP header không khớp.');
  const localName = await bytesAt(blob, entry.offset + 30, nameLength);
  const centralName = await bytesAt(blob, entry.central + 46, nameLength);
  if (!localName.every((byte, i) => byte === centralName[i])) throw new Error('Tên ở hai ZIP header không khớp.');
  const start = entry.offset + 30 + nameLength + h.getUint16(28, true);
  requireRange(entry.central, start, entry.packed);
  const packed = blob.slice(start, start + entry.packed);
  let content = packed;
  if (entry.method === 8) {
    const reader = packed.stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader();
    const parts = [];
    let size = 0;
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > entry.size) throw new Error('Dữ liệu giải nén dài hơn kích thước khai báo.');
        parts.push(value);
      }
    } catch (error) {
      await reader.cancel().catch(() => {});
      throw error;
    } finally {
      reader.releaseLock();
    }
    content = new Blob(parts);
  }
  if (content.size !== entry.size || await crcOf(content) !== entry.crc32) {
    throw new Error('Kích thước hoặc CRC32 của mục không khớp.');
  }
  return { blob: content, dataOffset: start };
}

async function parseDex(blob, out) {
  const bytes = await bytesAt(blob, 0, 112);
  const d = view(bytes);
  const endian = d.getUint32(40, true);
  if (![0x12345678, 0x78563412].includes(endian)) throw new Error('DEX endian tag không hợp lệ.');
  const little = endian === 0x12345678;
  const read = i => d.getUint32(i, little);
  const dexVersion = ascii(bytes.subarray(4, 7));
  const declared = read(32);
  const headerSize = read(36);
  if (headerSize < 112 || headerSize > declared || !/^\d{3}$/.test(dexVersion) || bytes[7]) {
    throw new Error('DEX header không hợp lệ.');
  }
  requireRange(blob.size, 0, declared);
  Object.assign(out.details, { 'Phiên bản DEX': dexVersion, 'Kích thước khai báo': declared, Endian: little ? 'Little' : 'Big', 'Adler-32 khai báo': hex(read(8), 8) });
  out.rows.push(row('header', 'DEX', 0, headerSize));
  if (Number(dexVersion) >= 41) {
    out.warnings.push('DEX 041+ có thể dùng nhiều header trong một container. Bản này hiển thị header đầu.');
    return;
  }
  const tables = [
    ['link data', 44, 1], ['string IDs', 56, 4], ['type IDs', 64, 4],
    ['proto IDs', 72, 12], ['field IDs', 80, 8], ['method IDs', 88, 8],
    ['class defs', 96, 32], ['data', 104, 1]
  ];
  for (const [name, at, width] of tables) {
    const count = read(at);
    const offset = read(at + 4);
    if (!count) continue;
    requireRange(declared, offset, count * width);
    out.rows.push(row(name, 'Bảng DEX', offset, count * width, { count }));
  }
  const map = read(52);
  if (!map) return;
  requireRange(declared, map, 4);
  const count = view(await bytesAt(blob, map, 4)).getUint32(0, little);
  if (count > 4096) throw new Error('DEX map có quá nhiều mục.');
  requireRange(declared, map, 4 + count * 12);
  const items = view(await bytesAt(blob, map + 4, count * 12));
  const kinds = { 0x1000: 'map list', 0x1001: 'type lists', 0x1002: 'annotation set refs', 0x1003: 'annotation sets', 0x2000: 'class data', 0x2001: 'code items', 0x2002: 'string data', 0x2003: 'debug info', 0x2004: 'annotations', 0x2005: 'encoded arrays', 0x2006: 'annotation directories', 0xf000: 'hidden API data' };
  for (let i = 0; i < count * 12; i += 12) {
    const type = items.getUint16(i, little);
    const offset = items.getUint32(i + 8, little);
    if (offset >= declared) throw new Error('Offset trong DEX map nằm ngoài file.');
    out.rows.push(row(kinds[type] || 'type ' + hex(type, 4), 'DEX map', offset, null, { count: items.getUint32(i + 4, little) }));
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
    throw new Error('ELF class, endianness hoặc phiên bản không hợp lệ.');
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
  Object.assign(out.details, { 'Kiến trúc': arch[machine] || hex(machine), Bit: wide ? 64 : 32, Endian: little ? 'Little' : 'Big', 'Entry VA': address(24), Segment: phCount, Section: shCount });
  const table = async (offset, size, count, minimum) => {
    if (!count) return new DataView(new ArrayBuffer(0));
    if (size < minimum) throw new Error('Kích thước bản ghi ELF không hợp lệ.');
    requireRange(blob.size, offset, count * size);
    const limit = Math.min(maxRows, Math.floor(maxDirectory / size));
    if (count > limit) out.warnings.push('Một bảng ELF vượt giới hạn và đã được cắt bớt.');
    return view(await bytesAt(blob, offset, Math.min(count, limit) * size));
  };
  const ph = await table(phoff, phSize, phCount, wide ? 56 : 32);
  const sh = await table(shoff, shSize, shCount, wide ? 64 : 40);
  const field = (t, i) => wide ? u64(t, i, little) : t.getUint32(i, little);
  const va = (t, i) => hex(wide ? t.getBigUint64(i, little) : t.getUint32(i, little));
  for (let i = 0; i < ph.byteLength; i += phSize) {
    const type = ph.getUint32(i, little);
    out.rows.push(row('Segment ' + i / phSize, 'PT ' + hex(type), field(ph, i + (wide ? 8 : 4)), field(ph, i + (wide ? 32 : 16)), { address: va(ph, i + (wide ? 16 : 8)) }));
  }
  const nameAt = namesIndex * shSize;
  let names = new Uint8Array();
  if (namesIndex && nameAt + shSize <= sh.byteLength) {
    const size = field(sh, nameAt + (wide ? 32 : 20));
    if (size <= maxDirectory) names = await bytesAt(blob, field(sh, nameAt + (wide ? 24 : 16)), size);
    else out.warnings.push('Bảng tên section vượt giới hạn 24 MiB.');
  }
  for (let i = 0; i < sh.byteLength && out.rows.length < maxRows; i += shSize) {
    const type = sh.getUint32(i + 4, little);
    const name = cstr(names, sh.getUint32(i, little), 4096) || 'Section ' + i / shSize;
    const size = field(sh, i + (wide ? 32 : 20));
    out.rows.push(row(name, 'SHT ' + hex(type), type === 8 ? null : field(sh, i + (wide ? 24 : 16)), size, { address: va(sh, i + (wide ? 16 : 12)) }));
  }
  if (phCount + shCount > maxRows) out.warnings.push('Bảng cấu trúc đã giới hạn ở 20.000 hàng.');
}

async function parsePe(blob, out, head) {
  if (head.length < 64) throw new Error('Thiếu DOS header.');
  const at = view(head).getUint32(60, true);
  const d = view(await bytesAt(blob, at, 24));
  if (d.getUint32(0, true) !== 0x4550) throw new Error('Không tìm thấy chữ ký PE.');
  const count = d.getUint16(6, true);
  const optSize = d.getUint16(20, true);
  const opt = view(await bytesAt(blob, at + 24, optSize));
  const magic = optSize >= 2 ? opt.getUint16(0, true) : 0;
  const wide = magic === 0x20b;
  const dirStart = wide ? 112 : 96;
  if ((!wide && magic !== 0x10b) || optSize < dirStart) throw new Error('PE optional header không được hỗ trợ hoặc bị cắt ngắn.');
  const machine = d.getUint16(4, true);
  const arch = { 332: 'x86', 34404: 'x86-64', 452: 'ARM', 43620: 'ARM64' };
  Object.assign(out.details, { 'Kiến trúc': arch[machine] || hex(machine), 'Optional header': wide ? 'PE32+' : 'PE32', 'Entry RVA': hex(opt.getUint32(16, true)), 'Image base': hex(wide ? opt.getBigUint64(24, true) : opt.getUint32(28, true)), Section: count });
  if (count > maxRows) throw new Error('Số section PE vượt giới hạn.');
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
  if (declared > available) out.warnings.push('Số data directory khai báo vượt kích thước optional header.');
  for (let i = 0; i < Math.min(declared, available, dirs.length); i++) {
    const address = opt.getUint32(dirStart + i * 8, true);
    const size = opt.getUint32(dirStart + i * 8 + 4, true);
    if (!address) continue;
    const section = sections.find(s => address >= s.va && address < s.va + s.size && size <= s.va + s.size - address);
    const offset = i === 4 ? address : section ? section.offset + address - section.va : null;
    out.rows.push(row(dirs[i], 'Data directory', offset, size, i === 4 ? {} : { address: hex(address) }));
  }
}

function parseUnity(blob, out, head) {
  const first = head.indexOf(0, 12);
  const second = head.indexOf(0, first + 1);
  if (first < 12 || second < 0 || second + 21 > head.length) {
    throw new Error('UnityFS header bị cắt ngắn hoặc vượt 512 byte.');
  }
  const d = view(head);
  const version = d.getUint32(8);
  const size = u64(d, second + 1, false);
  const packed = d.getUint32(second + 9);
  const unpacked = d.getUint32(second + 13);
  const flags = d.getUint32(second + 17);
  const end = second + 21;
  const headSize = version >= 7 ? Math.ceil(end / 16) * 16 : end;
  requireRange(blob.size, 0, size);
  const fromEnd = Boolean(flags & 0x80);
  const directory = fromEnd ? size - packed : headSize;
  requireRange(size, directory, packed);
  if (directory < headSize) throw new Error('Danh mục UnityFS chồng lên header.');
  Object.assign(out.details, {
    'Phiên bản format': version, 'Phiên bản player': cstr(head, 12), 'Phiên bản engine': cstr(head, first + 1),
    'Kích thước khai báo': size, 'Kích thước danh mục sau giải nén': unpacked,
    'Nén danh mục': ['Raw', 'LZMA', 'LZ4', 'LZ4HC', 'LZHAM'][flags & 0x3f] ?? (flags & 0x3f),
    Flags: hex(flags)
  });
  out.rows.push(row('Header', 'UnityFS', 0, headSize), row('Blocks info', 'Danh mục UnityFS', directory, packed));
}

function parseAndroidXml(blob, out, head) {
  if (head.length < 8) throw new Error('Thiếu XML header.');
  const d = view(head);
  const width = d.getUint16(2, true);
  const size = d.getUint32(4, true);
  if (width < 8 || width > size) throw new Error('Header XML không hợp lệ.');
  requireRange(blob.size, 0, size);
  out.details['Kích thước khai báo'] = size;
  out.rows.push(row('XML header', 'AXML', 0, width));
  return listXmlChunks(blob, out, width, size);
}

async function listXmlChunks(blob, out, offset, size) {
  if (size > maxDirectory) {
    out.warnings.push('XML vượt giới hạn 24 MiB. Chỉ đọc header.');
    return;
  }
  const data = view(await bytesAt(blob, 0, size));
  const labels = { 1: 'String pool', 0x100: 'Start namespace', 0x101: 'End namespace', 0x102: 'Start element', 0x103: 'End element', 0x104: 'CDATA', 0x180: 'Resource map' };
  while (offset < size && out.rows.length < maxRows) {
    requireRange(size, offset, 8);
    const type = data.getUint16(offset, true);
    const headerSize = data.getUint16(offset + 2, true);
    const length = data.getUint32(offset + 4, true);
    if (headerSize < 8 || length < headerSize) throw new Error('XML chunk sai kích thước.');
    requireRange(size, offset, length);
    out.rows.push(row(labels[type] || hex(type, 4), 'AXML chunk', offset, length, {
      headerSize, ...(type >= 0x100 && type <= 0x104 && headerSize >= 16 ? { line: data.getUint32(offset + 8, true) } : {})
    }));
    offset += length;
  }
  if (offset < size) out.warnings.push('Bảng XML đã giới hạn ở 20.000 hàng.');
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

export async function analyze(blob, name) {
  const head = await bytesAt(blob, 0, Math.min(blob.size, 512));
  const format = identify(head, name);
  const out = {
    schema: 'gameautopsy/1', version, name, format, size: blob.size, status: 'ok',
    details: {}, rows: [], warnings: []
  };
  const sample = Math.min(blob.size, 64 * 1024);
  if (sample) {
    out.details['Entropy đầu file (bit/byte)'] = entropy(await bytesAt(blob, 0, sample));
    out.details['Entropy cuối file (bit/byte)'] = entropy(await bytesAt(blob, blob.size - sample, sample));
    out.details['Kích thước mỗi mẫu entropy'] = sample;
  }
  try {
    switch (format) {
      case 'ZIP': await parseZip(blob, out); break;
      case 'DEX': await parseDex(blob, out); break;
      case 'ELF': await parseElf(blob, out, head); break;
      case 'PE': await parsePe(blob, out, head); break;
      case 'UnityFS': parseUnity(blob, out, head); break;
      case 'Android binary XML': await parseAndroidXml(blob, out, head); break;
      case 'Godot PCK':
        if (head.length >= 20) {
          const d = view(head);
          out.details['Phiên bản format'] = d.getUint32(4, true);
          out.details['Phiên bản engine'] = [8, 12, 16].map(at => d.getUint32(at, true)).join('.');
        } else throw new Error('Thiếu PCK header.');
        break;
      case 'IL2CPP metadata':
        if (head.length < 8) throw new Error('Thiếu IL2CPP header.');
        out.details['Phiên bản metadata'] = view(head).getUint32(4, true);
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

export async function sampleStrings(blob) {
  const limit = 4 * MiB;
  const maxResults = 500;
  const data = await bytesAt(blob, 0, Math.min(blob.size, limit));
  const candidates = [];
  const printable = byte => byte >= 32 && byte <= 126;
  function scan(start, step, encoding, valid) {
    let count = 0;
    for (let i = start; i < data.length;) {
      if (!valid(i)) {
        i += step;
        continue;
      }
      const first = i;
      let text = '';
      while (i < data.length && valid(i)) {
        if (text.length < 240) text += String.fromCharCode(data[i]);
        i += step;
      }
      const length = (i - first) / step;
      if (length >= 6) {
        candidates.push({ offset: first, text, length, encoding });
        if (++count > maxResults) break;
      }
    }
  }
  scan(0, 1, 'ASCII', i => printable(data[i]));
  for (const start of [0, 1]) scan(start, 2, 'UTF-16LE', i => printable(data[i]) && data[i + 1] === 0);
  candidates.sort((a, b) => a.offset - b.offset || a.encoding.localeCompare(b.encoding));
  return { scannedBytes: data.length, truncated: candidates.length > maxResults, rows: candidates.slice(0, maxResults) };
}

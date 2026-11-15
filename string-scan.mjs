const windowSize = 4 * 1024 * 1024;
const maxRows = 500;
const previewLimit = 240;
const encodings = { utf8: 'UTF-8', ascii: 'ASCII', utf16le: 'UTF-16LE', utf16be: 'UTF-16BE', ascii16le: 'UTF-16LE' };
const unicodeGraphic = /^[\p{L}\p{M}\p{N}\p{P}\p{S}\p{Zs}]$/u;
const continuationByte = byte => (byte & 0xc0) === 0x80;

function utf8(bytes, index) {
  const lead = bytes[index];
  if (lead < 0x80) return lead;
  const b = bytes[index + 1];
  if (lead < 0xc2 || lead >= 0xf5 || !continuationByte(b)) return -1;
  if (lead < 0xe0) return ((lead & 31) << 6) | (b & 63);
  const c = bytes[index + 2];
  if (!continuationByte(c)) return -1;
  if (lead < 0xf0) {
    const value = ((lead & 15) << 12) | ((b & 63) << 6) | (c & 63);
    return value >= 0x800 && (value < 0xd800 || value > 0xdfff) ? value : -1;
  }
  const d = bytes[index + 3];
  if (!continuationByte(d)) return -1;
  const value = ((lead & 7) << 18) | ((b & 63) << 12) | ((c & 63) << 6) | (d & 63);
  return value >= 0x10000 && value <= 0x10ffff ? value : -1;
}

function utf16(bytes, index, little) {
  const unit = at => little ? bytes[at] | bytes[at + 1] << 8 : bytes[at] << 8 | bytes[at + 1];
  if (index + 1 >= bytes.length) return -1;
  const first = unit(index);
  if (first < 0xd800 || first >= 0xe000) return first;
  if (first >= 0xdc00 || index + 3 >= bytes.length) return -1;
  const second = unit(index + 2);
  if (second < 0xdc00 || second > 0xdfff) return -1;
  return 0x10000 + ((first - 0xd800) << 10) + second - 0xdc00;
}

function printable(code) {
  if (code < 0x80) return code >= 0x20 && code < 0x7f;
  return unicodeGraphic.test(String.fromCodePoint(code));
}

function scanWindow(bytes, base, stop, fileSize, { mode, minLength, continuation }, progress) {
  const read = {
    ascii: index => bytes[index] ?? -1,
    ascii16le: index => bytes[index + 1] === 0 && bytes[index] < 128 ? bytes[index] : -1,
    utf8: index => utf8(bytes, index),
    utf16le: index => utf16(bytes, index, true),
    utf16be: index => utf16(bytes, index, false)
  }[mode];
  const wide = mode.includes('16');
  const width = wide ? code => code > 0xffff ? 4 : 2 :
    code => code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
  const rows = [];
  let cursor = 0;
  let start = 0;
  let length = 0;
  let text = '';
  let nonAscii = false;
  let nextProgress = 0;
  let next = null;
  const emit = (end, continues) => {
    if (length >= minLength || (continuation && length)) {
      rows.push({
        offset: base + start, byteLength: end - start, length, text,
        encoding: mode === 'utf8' && !nonAscii ? 'ASCII' : encodings[mode], continuation, continues
      });
    }
    continuation = false;
    length = 0;
    text = '';
    nonAscii = false;
  };

  while (cursor < stop) {
    if (cursor >= nextProgress) {
      progress({ stage: 'Scanning ' + encodings[mode], done: cursor, total: stop, unit: 'bytes' });
      nextProgress = cursor + 1024 * 1024;
    }
    const code = read(cursor);
    const graphic = !(mode === 'ascii' && code > 127) && printable(code);
    if (graphic) {
      if (length === 0) {
        start = cursor;
        continuation = continuation && cursor === 0;
      }
      if (length < previewLimit) text += String.fromCodePoint(code);
      length++;
      nonAscii ||= code > 127;
      cursor += width(code);
    } else {
      if (length) emit(cursor, false);
      cursor = Math.min(bytes.length, cursor + (wide ? 2 : code < 0 ? 1 : width(code)));
      if (rows.length >= maxRows) {
        if (base + cursor < fileSize) next = { offset: base + cursor, continuation: false };
        break;
      }
    }
  }
  if (length) {
    const lookahead = base + cursor < fileSize ? read(cursor) : -1;
    const continues = printable(lookahead) && (mode !== 'ascii' || lookahead < 128);
    const keep = length >= minLength || continuation;
    if (continues && !keep) {
      // Retry from the beginning of a short run that straddles the window.
      next = { offset: base + start, continuation: false };
    } else {
      emit(cursor, continues);
      if (continues) next = { offset: base + cursor, continuation: true };
    }
  }
  progress({ stage: 'Scanning ' + encodings[mode], done: Math.min(cursor, stop), total: stop, unit: 'bytes' });
  if (!next && base + cursor < fileSize) next = { offset: base + cursor, continuation: false };
  return { mode, minLength, from: base, end: base + cursor, scannedBytes: cursor, next,
    limited: rows.length >= maxRows && next !== null, rows };
}

async function readWindow(blob, offset) {
  const remaining = blob.size - offset;
  const buffer = await blob.slice(offset, offset + Math.min(remaining, windowSize + 8)).arrayBuffer();
  return new Uint8Array(buffer);
}

export async function scanStrings(blob, options = {}, progress = () => {}) {
  const { mode = 'utf8', offset = 0, minLength = 6, continuation = false } = options;
  if (!['utf8', 'utf16le', 'utf16be', 'ascii'].includes(mode)) throw new Error('Select a supported string encoding.');
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > blob.size) throw new Error('String scan offset is outside the file.');
  if (!Number.isInteger(minLength) || minLength < 2 || minLength > 128) throw new Error('Minimum length must be from 2 to 128 characters.');
  const bytes = await readWindow(blob, offset);
  return scanWindow(bytes, offset, Math.min(bytes.length, windowSize), blob.size,
    { mode, minLength, continuation }, progress);
}

export async function sampleStrings(blob, progress = () => {}) {
  const bytes = await readWindow(blob, 0);
  const stop = Math.min(bytes.length, windowSize);
  const pass = (base, mode) => scanWindow(bytes.subarray(base), base, Math.max(0, stop - base), blob.size,
    { mode, minLength: 6, continuation: false }, progress);
  const scans = [pass(0, 'utf8'), pass(0, 'ascii16le')];
  if (stop > 1) scans.push(pass(1, 'ascii16le'));
  const rows = scans.flatMap(scan => scan.rows).sort((a, b) => a.offset - b.offset || a.encoding.localeCompare(b.encoding));
  return { mode: 'sample', from: 0, end: stop, scannedBytes: stop, truncated: rows.length > maxRows || scans.some(scan => scan.limited),
    passes: scans.map(({ mode, from, end, limited }) => ({ mode, from, end, limited })), rows: rows.slice(0, maxRows) };
}

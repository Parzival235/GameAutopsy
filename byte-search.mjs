const MiB = 1024 * 1024;
const chunkSize = MiB;
const scanLimit = 64 * MiB;
const resultLimit = 200;
const probeLimit = 8_000_000;

export function parsePattern(query, mode) {
  if (mode === 'text') {
    const bytes = [...new TextEncoder().encode(query)];
    if (bytes.length && bytes.length <= 128) return bytes;
    throw new Error('Enter 1–128 bytes of UTF-8 text.');
  }
  if (mode !== 'hex') throw new Error('Unknown search mode.');
  const tokens = query.trim().split(/\s+/);
  if (tokens.length > 128 || tokens.some(t => !/^(?:[0-9a-f]{2}|\?\?)$/i.test(t))) {
    throw new Error('Enter up to 128 space-separated hex bytes, using ?? for a wildcard.');
  }
  const pattern = tokens.map(t => t === '??' ? null : Number.parseInt(t, 16));
  if (pattern.every(b => b === null)) throw new Error('Include at least one fixed byte.');
  return pattern;
}

export async function searchBytes(blob, query, mode, from = 0, progress = () => {}) {
  const { probes, ...result } = await scanPattern(blob, parsePattern(query, mode), from, {}, progress);
  return result;
}

export async function scanPattern(blob, pattern, from, {
  maxOffsets = scanLimit, maxHits = resultLimit, maxProbes = probeLimit
} = {}, progress = () => {}) {
  if (!Number.isSafeInteger(from) || from < 0 || from > blob.size) throw new Error('Search offset is outside the file.');
  const fixed = pattern.flatMap((value, index) => value === null ? [] : [[index, value]]);
  const [anchor, value] = fixed[0];
  const end = Math.min(Math.max(from, blob.size - pattern.length + 1), from + maxOffsets);
  const offsets = [];
  let probes = 0;
  const update = done => progress({ stage: 'Searching byte offsets', done, total: end - from, unit: 'offsets' });
  const result = stop => {
    update(stop - from);
    return { from, end: stop, length: pattern.length, offsets, probes,
      next: stop < blob.size - pattern.length + 1 ? stop : null };
  };
  for (let at = from; at < end; at += chunkSize) {
    if ((at - from) % (4 * MiB) === 0) update(at - from);
    const count = Math.min(chunkSize, end - at);
    const data = new Uint8Array(await blob.slice(at, at + count + pattern.length - 1).arrayBuffer());
    for (let i = data.indexOf(value, anchor); i >= 0 && i - anchor < count; i = data.indexOf(value, i + 1)) {
      const start = i - anchor;
      let matches = true;
      for (let j = 1; j < fixed.length; j++) {
        probes++;
        const [index, byte] = fixed[j];
        if (data[start + index] !== byte) {
          matches = false;
          break;
        }
        if (probes >= maxProbes && j + 1 < fixed.length) {
          // Retry this position next pass if it could still match.
          return result(at + start);
        }
      }
      if (matches) offsets.push(at + start);
      if (offsets.length === maxHits || probes >= maxProbes) return result(at + start + 1);
    }
  }
  return result(end);
}

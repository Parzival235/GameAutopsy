const MiB = 1024 * 1024;
const windowSize = 128 * MiB;
const partSize = MiB;
const maxRanges = 2048;
const read = async (blob, start, end) => new Uint8Array(await blob.slice(start, end).arrayBuffer());

export async function compareBytes(before, after, start = 0, onProgress = () => {}) {
  const size = Math.max(before.size, after.size);
  if (!Number.isSafeInteger(start) || start < 0 || start > size) throw new Error('Comparison offset is outside both files.');
  const end = Math.min(start + windowSize, size);
  const overlap = Math.min(before.size, after.size);
  const sharedEnd = Math.min(end, overlap);
  const result = {
    start, end, next: end < size ? end : null, beforeSize: before.size, afterSize: after.size,
    changed: 0, beforeOnly: 0, afterOnly: 0, totalRanges: 0, ranges: []
  };
  let runStart = -1;
  function add(offset, stop, kind) {
    result.totalRanges++;
    if (result.ranges.length < maxRanges) result.ranges.push({ offset, length: stop - offset, kind });
  }

  for (let at = start; at < sharedEnd; at += partSize) {
    const stop = Math.min(at + partSize, sharedEnd);
    const [left, right] = await Promise.all([read(before, at, stop), read(after, at, stop)]);
    for (let i = 0; i < left.length; i++) {
      if (left[i] !== right[i]) {
        result.changed++;
        if (runStart < 0) runStart = at + i;
      } else if (runStart >= 0) {
        add(runStart, at + i, 'changed');
        runStart = -1;
      }
    }
    if ((at - start) % (8 * MiB) === 0) onProgress({ scanned: stop - start, total: end - start });
  }
  if (runStart >= 0) add(runStart, sharedEnd, 'changed');

  const tail = Math.max(start, overlap);
  if (tail < end) {
    const kind = before.size > after.size ? 'beforeOnly' : 'afterOnly';
    result[kind] = end - tail;
    add(tail, end, kind);
  }
  result.omittedRanges = result.totalRanges - result.ranges.length;
  return result;
}

export async function previewDiff(before, after, offset) {
  const size = Math.max(before.size, after.size);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > size || (offset === size && size)) {
    throw new Error('Preview offset is outside both files.');
  }
  const end = offset + 128;
  const [left, right] = await Promise.all([read(before, offset, end), read(after, offset, end)]);
  return { offset, before: [...left], after: [...right] };
}

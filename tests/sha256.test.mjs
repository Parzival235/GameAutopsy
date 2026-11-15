import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { hashSha256 } from '../sha256.mjs';

test('streamed SHA-256 agrees with Node at padding and chunk boundaries', async () => {
  for (const size of [0, 1, 55, 56, 63, 64, 65, 1024 * 1024 + 55, 4 * 1024 * 1024 + 56]) {
    const data = Buffer.alloc(size);
    for (let i = 0; i < size; i++) data[i] = (i ^ (i >>> 8)) & 255;
    const source = new Blob([data]);
    const progress = [];
    const readSizes = [];
    const bounded = { size, slice(start, end) {
      readSizes.push(end - start);
      return source.slice(start, end);
    } };
    assert.equal(await hashSha256(bounded, entry => progress.push(entry)), createHash('sha256').update(data).digest('hex'));
    assert.ok(readSizes.every(length => length <= 1024 * 1024));
    assert.equal(progress[0].done, 0);
    assert.equal(progress.at(-1).done, size);
  }
});

test('streamed SHA-256 cancels without completing and rejects a short read', async () => {
  const controller = new AbortController();
  const blob = new Blob([new Uint8Array(5 * 1024 * 1024)]);
  await assert.rejects(hashSha256(blob, ({ done }) => {
    if (done >= 4 * 1024 * 1024) controller.abort();
  }, controller.signal), { name: 'AbortError' });
  await assert.rejects(hashSha256({ size: 64, slice: () => new Blob(['short']) }), /ended/);
});

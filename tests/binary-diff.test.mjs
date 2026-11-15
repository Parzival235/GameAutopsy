import test from 'node:test';
import assert from 'node:assert/strict';
import { compareBytes, previewDiff } from '../binary-diff.mjs';

test('byte diff merges a run across a read boundary and separates tail bytes', async () => {
  const boundary = 1024 * 1024;
  const before = new Blob([new Uint8Array(boundary + 6)]);
  const next = new Uint8Array(boundary + 8);
  next.fill(0xa5, boundary - 2, boundary + 2);
  next[boundary + 4] = 0x42;
  const after = new Blob([next]);
  const result = await compareBytes(before, after);
  assert.equal(result.changed, 5);
  assert.equal(result.afterOnly, 2);
  assert.deepEqual(result.ranges, [
    { offset: boundary - 2, length: 4, kind: 'changed' },
    { offset: boundary + 4, length: 1, kind: 'changed' },
    { offset: boundary + 6, length: 2, kind: 'afterOnly' }
  ]);
  assert.deepEqual(await previewDiff(before, after, boundary + 6), { offset: boundary + 6, before: [], after: [0, 0] });
  assert.equal((await compareBytes(after, before, boundary + 6)).beforeOnly, 2);
});

test('byte diff retains exact counts when too many ranges are listed', async () => {
  const before = new Blob([new Uint8Array(8000)]);
  const after = new Blob([Uint8Array.from({ length: 8000 }, (_, i) => i % 2)]);
  const result = await compareBytes(before, after);
  assert.equal(result.changed, 4000);
  assert.equal(result.totalRanges, 4000);
  assert.equal(result.ranges.length, 2048);
  assert.equal(result.omittedRanges, 1952);
  const equal = await compareBytes(before, before);
  assert.equal(equal.totalRanges, 0);
  assert.equal(equal.next, null);
});

test('byte diff comparison window can resume without counting earlier offsets again', async () => {
  const before = new Blob();
  const after = { size: 129 * 1024 * 1024, slice: () => { throw new Error('Should never read bytes outside the overlap'); } };
  const first = await compareBytes(before, after);
  assert.equal(first.next, 128 * 1024 * 1024);
  const second = await compareBytes(before, after, first.next);
  assert.equal(second.afterOnly, 1024 * 1024);
  assert.equal(second.next, null);
  await assert.rejects(compareBytes(before, after, -1), /outside both files/);
});

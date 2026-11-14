import test from 'node:test';
import assert from 'node:assert/strict';
import { compareArchives } from '../compare.mjs';
import { interpretBytes } from '../hex.mjs';

const entry = (name, overrides) => ({
  name, kind: 'Stored', size: 50, packed: 50, method: 0, flags: 0, crc32: 10, offset: 0, ...overrides
});
const archive = (name, rows) => ({ name, rows, format: 'ZIP', status: 'ok', details: { 'Declared entries': rows.length } });

test('ZIP comparison separates content, packing, offsets and ambiguous entries', () => {
  const a = archive('a.apk', [
    entry('gone'), entry('changed'), entry('packed'), entry('duplicate'), entry('duplicate'),
    entry('moved'), entry('same'), entry('locked', { flags: 1 }), entry('assets/', { kind: 'Directory' })
  ]);
  const b = archive('b.apk', [
    entry('new'), entry('changed', { crc32: 7 }), entry('packed', { method: 8, packed: 25 }),
    entry('duplicate'), entry('moved', { offset: 30 }), entry('same'), entry('locked', { flags: 1 })
  ]);
  const result = compareArchives(a, b);
  assert.deepEqual(result.counts, {
    added: 1, removed: 1, changed: 1, repacked: 1, moved: 1, matched: 1, ambiguous: 1, encrypted: 1
  });
  assert.equal(result.rows.find(row => row.name === 'packed').packedDelta, -25);
  assert.equal(result.rows.find(row => row.name === 'duplicate').before.length, 2);
  assert.equal(result.rows.some(row => row.name === 'same'), false);
  assert.throws(() => compareArchives(a, { ...b, rows: [] }), /complete ZIP directories/);
});

test('hex interpretation handles endianness, signed values and incomplete words', () => {
  assert.equal(interpretBytes([0xff, 0x01], true).u16, 511);
  assert.equal(interpretBytes([0xff, 0x01], false).i16, -255);
  assert.equal(interpretBytes([0xff, 0x01], true).i8, -1);
  assert.equal(interpretBytes([0xff, 0x01], true).f32, '—');
  assert.equal(interpretBytes([0, 0, 0, 0, 0, 0, 0, 0x80], true).i64, -(2n ** 63n));
  assert.equal(interpretBytes([0x3f, 0x80, 0, 0], false).f32, 1);
});

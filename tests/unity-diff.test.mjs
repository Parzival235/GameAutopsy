import assert from 'node:assert/strict';
import test from 'node:test';
import { analyze } from '../formats.mjs';
import { compareUnityFiles } from '../unity-diff.mjs';

const cameraPath = '-9223372036854775801';

// Length-limited type and object tables for serializer v22.
function serialized(objects, { move = 0, external = [], typeTrees = true, fieldName = 'layer' } = {}) {
  const meta = [];
  let length = 0;
  function push(data) { meta.push(data); length += data.length; }
  function i32(value) { const b = Buffer.alloc(4); b.writeInt32LE(value); push(b); }
  function i64(value) { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(value)); push(b); }
  const string = value => push(Buffer.from(value + '\0'));
  string('2022.1.20f1');
  i32(13);
  push(Buffer.from([Number(typeTrees)]));
  i32(1);
  i32(1); // GameObject
  push(Buffer.from([0, 255, 255])); // not stripped, script index -1
  push(Buffer.alloc(16, fieldName === 'layer' ? 1 : 2));
  if (typeTrees) {
    const nodes = [
      [0, 'GameObject', 'Base', -1], [1, 'int', fieldName, 4], [1, 'PPtr<Object>', 'target', 12],
      [2, 'int', 'm_FileID', 4], [2, 'SInt64', 'm_PathID', 8]
    ];
    const data = Buffer.alloc(nodes.length * 32);
    const strings = [];
    let stringBytes = 0;
    const offset = value => {
      const raw = Buffer.from(value + '\0');
      const start = stringBytes;
      stringBytes += raw.length;
      strings.push(raw);
      return start;
    };
    for (const [index, [depth, type, name, size]] of nodes.entries()) {
      const at = index * 32;
      data[at + 2] = depth;
      data.writeUInt32LE(offset(type), at + 4);
      data.writeUInt32LE(offset(name), at + 8);
      data.writeInt32LE(size, at + 12);
    }
    i32(nodes.length);
    i32(stringBytes);
    push(data);
    for (const s of strings) push(s);
    i32(0);
  }
  i32(objects.length);
  push(Buffer.alloc((4 - length % 4) % 4));
  for (const [index, [id]] of objects.entries()) {
    i64(id);
    i64(index * 16);
    i32(16);
    i32(0);
  }
  i32(0);
  i32(external.length);
  for (const path of external) {
    string('');
    push(Buffer.alloc(16));
    i32(0);
    string(path);
  }
  i32(0);
  string('');
  const header = Buffer.alloc(48);
  const dataOffset = Math.ceil((48 + length) / 16) * 16 + move;
  header.writeUInt32BE(22, 8);
  header.writeUInt32BE(length, 20);
  header.writeBigUInt64BE(BigInt(dataOffset + 16 * objects.length), 24);
  header.writeBigUInt64BE(BigInt(dataOffset), 32);
  const data = Buffer.alloc(16 * objects.length);
  for (const [index, [, layer, fileId = 0, target = 0]] of objects.entries()) {
    data.writeInt32LE(layer, 16 * index);
    data.writeInt32LE(fileId, 16 * index + 4);
    data.writeBigInt64LE(BigInt(target), 16 * index + 8);
  }
  return new Blob([header, ...meta, Buffer.alloc(dataOffset - 48 - length), data]);
}

async function node(objects, options, name = 'fixture.assets') {
  const blob = serialized(objects, options);
  return { blob, report: await analyze(blob, name) };
}

test('Unity comparison proves field values while treating relocated identical data as moved', async () => {
  const old = await node([[cameraPath, 2], [5, 9], [6, 80]], {}, 'baseline.assets');
  const next = await node([[cameraPath, 7], [5, 9], [8, 99]], { move: 32 }, 'candidate.assets');
  const diff = await compareUnityFiles(old, next);
  assert.equal(diff.coverage.pairs, 2);
  assert.equal(diff.coverage.fieldPairs, 1);
  assert.equal(diff.counts.fieldsChanged, 1);
  assert.equal(diff.counts.moved, 1);
  assert.equal(diff.counts.added, 1);
  assert.equal(diff.counts.removed, 1);
  const [entry] = diff.rows;
  assert.equal(entry.pathId, cameraPath);
  assert.equal(entry.fieldDiff.complete, true);
  const [field] = entry.fieldDiff.fields;
  assert.deepEqual(field.path, ['layer']);
  assert.equal(field.before.value, 2);
  assert.equal(field.after.value, 7);
  assert.equal(field.before.offset, entry.before.offset);
  assert.equal(field.after.offset - field.before.offset, 32);
  assert.equal(diff.rows[1].bytes.equal, true);
  assert.equal(diff.rows[1].fieldDiff, undefined);
});

test('Unity comparison resolves remapped external pointers and detects a target change with equal object bytes', async () => {
  const a = await node([[1, 0, 1, 9]], { external: ['archive:/old', 'archive:/new'] });
  const renumbered = await node([[1, 0, 2, 9]], { external: ['archive:/new', 'archive:/old'] });
  const retargeted = await node([[1, 0, 1, 9]], { external: ['archive:/new', 'archive:/old'] });
  const unchanged = (await compareUnityFiles(a, renumbered)).rows[0];
  assert.equal(unchanged.status, 'fieldsEqual');
  const changed = (await compareUnityFiles(a, retargeted)).rows[0];
  assert.equal(changed.bytes.equal, true);
  assert.equal(changed.status, 'fieldsChanged');
  assert.equal(changed.fieldDiff.fields[0].kind, 'referenceChanged');
  assert.equal(changed.fieldDiff.fields[0].after.reference.path, 'archive:/new');
});

test('Unity comparison records ambiguous IDs, incomplete coverage and byte-only differences', async () => {
  const a = await node([[1, 8], [2, 0], [3, 2], [3, 8]], { typeTrees: false });
  const b = await node([[1, 9], [3, 3]], { typeTrees: false });
  b.report.unitySerialized.objectCount++;
  const result = await compareUnityFiles(a, b);
  assert.equal(result.counts.bytesChanged, 1);
  assert.equal(result.counts.removed, 0);
  assert.deepEqual(result.coverage.skipped, { missingEmbeddedTypeTree: 1, incompleteObjectTable: 1, duplicatePathId: 1 });
  const focused = await compareUnityFiles(a, b, '0001');
  assert.deepEqual(focused.rows.map(row => row.pathId), ['1']);
  await assert.rejects(compareUnityFiles(a, b, '9223372036854775808'), /64-bit/);
});

test('Unity comparison caps paired work and can focus a Path ID beyond the bulk limit', async () => {
  const objects = Array.from({ length: 775 }, (_, index) => [index + 1, index]);
  const a = await node(objects);
  const b = await node(objects);
  const bulk = await compareUnityFiles(a, b);
  assert.equal(bulk.coverage.pairs, 768);
  assert.equal(bulk.counts.byteEqual, 768);
  assert.equal(bulk.coverage.skipped.comparisonBudget, 7);
  const single = await compareUnityFiles(a, b, '775');
  assert.equal(single.rows[0].status, 'byteEqual');
  assert.equal(single.coverage.pairs, 1);
});

test('Unity comparison stays within report limits on deterministically mutated inputs', async () => {
  const baseline = await node([[1, 1, 1, 5], [2, 9]], { external: ['archive:/sibling'] });
  const original = new Uint8Array(await baseline.blob.arrayBuffer());
  let state = 0x43a1;
  for (let iteration = 0; iteration < 72; iteration++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    const copy = original.slice(0, iteration % 4 === 0 ? state % original.length : original.length);
    if (copy.length && iteration % 4 !== 0) copy[state % copy.length] ^= 1 << ((state >>> 24) % 8);
    const blob = new Blob([copy]);
    const report = await analyze(blob, 'mutated.assets');
    if (!report.unitySerialized) continue;
    const result = await compareUnityFiles(baseline, { blob, report });
    assert.ok(result.rows.length <= result.coverage.limits.rows);
    assert.ok(result.coverage.bytesBudgeted <= result.coverage.limits.bytes);
    assert.doesNotThrow(() => JSON.stringify(result));
  }
});

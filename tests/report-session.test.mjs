import test from 'node:test';
import assert from 'node:assert/strict';
import { createReportSession } from '../report-session.mjs';

test('full report keeps distinct routes and enriches a reopened file', () => {
  const session = createReportSession();
  const root = { route: [], path: ['game.apk'], report: { version: '0.6.0' } };
  const first = { route: [1], path: ['game.apk', 'data'], report: { size: 1, strings: { rows: [] } } };
  const other = { route: [2], path: ['game.apk', 'data'], report: { size: 2 } };
  session.retainFile(first);
  session.retainFile(other);
  session.record(first, 'byteSearch', { offsets: [0] }, { query: '00', mode: 'hex' });
  const result = session.snapshot(root, { ...first, report: { size: 1, sha256: 'new' } }, [], { containers: 1 });
  assert.deepEqual(result.files.map(item => item.route), [[1], [2], []]);
  assert.deepEqual(result.files[0].report, { size: 1, strings: { rows: [] }, sha256: 'new' });
  assert.equal(result.operations[0].input.query, '00');
  assert.deepEqual(result.active.route, [1]);
  assert.equal(result.inventory.containers, 1);
});

test('report records omission counts and preserves root and active reports', () => {
  const session = createReportSession();
  const root = { route: [], path: ['game.apk'], report: { version: '0.6.0' } };
  for (let i = 0; i < 100; i++) session.record(root, 'hexPreview', { offset: i });
  const result = session.snapshot(root, root, [], null);
  assert.equal(result.operations.length, 96);
  assert.equal(result.omitted.operations, 4);
  assert.equal(result.inventory, null);
  assert.equal(result.files.length, 1);
});

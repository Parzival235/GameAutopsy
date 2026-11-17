import assert from 'node:assert/strict';
import test from 'node:test';
import { analyze } from '../formats.mjs';
import { parsePattern, scanPattern } from '../byte-search.mjs';
import { zip } from './zip-fixture.mjs';

test('archive search keeps the filter and exact cursor while opening round-trip matches', async () => {
  let receive, reply, id = 0;
  globalThis.self = {
    addEventListener(event, handler) { assert.equal(event, 'message'); receive = handler; },
    postMessage(message) { if (!message.progress) reply = message; }
  };
  try {
    await import('../worker.mjs');
    async function call(action, args, error) {
      await receive({ data: { id: ++id, action, ...args } });
      assert.equal(reply.id, id);
      if (error) { assert.match(reply.error, error); return; }
      assert.equal(reply.error, undefined);
      return reply.data;
    }
    const a = zip([['assets/map.txt', 'XY'.repeat(153), 8], ['assets/map.txt', 'roadXY'], ['notes.txt', 'XY']]);
    const b = zip([['assets/map.txt', 'XY elsewhere']]);
    const outer = zip([['base.apk', a, 8], ['config.apk', b]]);
    await call('open', { file: new File([outer], 'sample.apks') });
    await call('inventory-search', { query: 'XY', mode: 'text' }, /Index the root/);
    await call('inventory');
    const first = await call('inventory-search', { query: '58 ??', mode: 'hex', pathFilter: 'base.apk map.txt', category: 'Text / data' });
    assert.equal(first.members, 2);
    assert.equal(first.matches, 150);
    assert.deepEqual(first.next, { member: 0, offset: 299 });
    assert.deepEqual(first.hits[0].path, ['sample.apks', 'base.apk', 'assets/map.txt']);
    assert.equal(first.hits[0].source.dataOffset, 30 + 'assets/map.txt'.length);
    await call('inventory-open', { index: first.hits[0].id });
    assert.deepEqual((await call('hex', { offset: 298 })).bytes.slice(0, 2), [0x58, 0x59]);
    const second = await call('inventory-search-more');
    assert.equal(second.matches, 4);
    assert.deepEqual(second.hits.map(hit => hit.offsets), [[300, 302, 304], [4]]);
    assert.notDeepEqual(second.hits[0].route, second.hits[1].route);
    assert.equal(second.next, null);
    const report = JSON.parse(await (await call('full-report')).output.text());
    assert.deepEqual(report.operations.filter(op => op.kind === 'inventorySearch').map(op => op.result.matches), [150, 4]);
    await call('inventory');
    await call('inventory-search-more', {}, /no inventory search/);
    await call('inventory-search', { query: '??', mode: 'hex', pathFilter: 'missing' }, /fixed byte/);
  } finally {
    delete globalThis.self;
  }
});

test('corrupt nested inputs and protected entries produce explicit coverage', async () => {
  const { buildInventory } = await import('../inventory.mjs');
  const { planInventorySearch, searchInventory } = await import('../inventory-search.mjs');
  const data = zip([['bad.txt', 'needle'], ['protected.txt', 'needle'], ['a.txt', 'one needle two']]);
  const original = await analyze(new Blob([data]), 'test.zip');
  data[original.rows[0].offset + 30 + 'bad.txt'.length] ^= 1;
  const protectedRow = original.rows[1];
  data[protectedRow.central + 8] |= 1;
  const blob = new Blob([data]);
  const root = { blob, report: await analyze(blob, 'test.zip') };
  const result = await searchInventory(root, planInventorySearch(await buildInventory(root), 'needle', 'text'));
  assert.equal(result.completed, 1);
  assert.equal(result.visited, 3);
  assert.match(result.skipped[0].reason, /CRC32/);
  assert.match(result.skipped[1].reason, /metadata only/);
  assert.deepEqual(result.hits.map(hit => hit.offsets), [[4]]);
});

test('byte scan resumes at a potential match paused by the remaining probe budget', async () => {
  const data = new Blob(['AXYZ']);
  const pattern = parsePattern('AXYZ', 'text');
  const first = await scanPattern(data, pattern, 0, { maxProbes: 2 });
  assert.equal(first.next, 0);
  assert.deepEqual(first.offsets, []);
  assert.deepEqual((await scanPattern(data, pattern, first.next)).offsets, [0]);
});

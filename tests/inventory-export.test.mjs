import assert from 'node:assert/strict';
import test from 'node:test';
import { analyze, openZipMember } from '../formats.mjs';
import { buildInventory } from '../inventory.mjs';
import { exportInventory, exportLimit } from '../inventory-export.mjs';
import { zip } from './zip-fixture.mjs';

test('worker exports independent nested members and preserves selection provenance in full JSON', async () => {
  let receive, last, id = 0;
  globalThis.self = {
    addEventListener(event, handler) {
      assert.equal(event, 'message');
      receive = handler;
    },
    postMessage(message) { if (!message.progress) last = message; }
  };
  try {
    await import('../worker.mjs');
    async function call(action, args) {
      await receive({ data: { id: ++id, action, ...args } });
      assert.equal(last.id, id);
      assert.equal(last.error, undefined);
      return last.data;
    }
    const source = zip([
      ['base.apk', zip([
        ['assets/quest.txt', 'forest', 8], ['assets/QUEST.txt', 'desert'],
        ['assets/quest.txt', 'lake'], ['assets/quest.txt/sub', 'file folder overlap'],
        ['../C:/NUL.txt', 'safe name']
      ]), 8],
      ['config.apk', zip([['assets/quest.txt', 'village']])]
    ]);
    await call('open', { file: new File([source], 'game.apks') });
    const inventory = await call('inventory');
    const rows = inventory.rows.filter(row => row.path.length > 1);
    await call('inventory-open', { index: rows[0].id });
    const { output, manifest } = await call('inventory-export', { indices: rows.map(row => row.id).reverse() });
    assert.equal(manifest.requested, 6);
    assert.deepEqual(manifest.skipped, []);
    assert.deepEqual(manifest.entries.map(row => row.route), rows.map(row => row.route));
    const paths = manifest.entries.map(row => row.output);
    assert.deepEqual(paths.slice(0, 4).map(path => path.split('/')[0]), ['files', 'collisions', 'collisions', 'collisions']);
    assert.notEqual(paths[0], paths.at(-1));
    assert.ok(paths.every(path => !/(?:^|\/)\.\.(?:$|\/)|:|\\/.test(path)));
    const report = await analyze(output, 'selection.zip');
    assert.equal(report.status, 'ok');
    assert.equal(report.rows.length, 7);
    const exported = await Promise.all(report.rows.map(async row => (await openZipMember(output, row)).blob.text()));
    assert.deepEqual(exported.slice(0, 6), ['forest', 'desert', 'lake', 'file folder overlap', 'safe name', 'village']);
    assert.deepEqual(JSON.parse(exported[6]), manifest);
    assert.equal(await (await call('download')).text(), 'forest');
    const full = JSON.parse(await (await call('full-report')).output.text());
    assert.deepEqual(full.operations.find(operation => operation.kind === 'inventoryExport').result, manifest);
  } finally {
    delete globalThis.self;
  }
});

test('a bad member is skipped and the count and payload limits are enforced', async () => {
  const source = zip([['valid.txt', 'text'], ['bad.txt', 'bad payload'], ['empty.txt', '']]);
  const original = await analyze(new Blob([source]), 'sample.zip');
  source[original.rows[1].offset + 30 + 'bad.txt'.length] ^= 1;
  const blob = new Blob([source]);
  const root = { blob, report: await analyze(blob, 'sample.zip') };
  const inventory = await buildInventory(root);
  const result = await exportInventory(root, inventory, [2, 1, 0, 1]);
  assert.equal(result.manifest.requested, 3);
  assert.equal(result.manifest.entries.length, 2);
  assert.match(result.manifest.skipped[0].reason, /CRC32/);
  assert.equal((await exportInventory(root, inventory, [1])).output, null);
  await assert.rejects(exportInventory(root, inventory, [999]), /current inventory/);
  await assert.rejects(exportInventory(root, inventory, Array(exportLimit.entries + 1).fill(0)), /Select between/i);
  inventory.rows[0].size = exportLimit.payloadBytes + 1;
  const oversized = await exportInventory(root, inventory, [0]);
  assert.equal(oversized.output, null);
  assert.match(oversized.manifest.skipped[0].reason, /64 MiB/);
});

import assert from 'node:assert/strict';
import test from 'node:test';
import { zip } from './zip-fixture.mjs';

test('worker compares nested entry bytes, retains provenance, and saves both decoded sides', async () => {
  let receive;
  let last;
  globalThis.self = {
    addEventListener(event, handler) {
      assert.equal(event, 'message');
      receive = handler;
    },
    postMessage(message) {
      if (!message.progress) last = message;
    }
  };
  try {
    await import('../worker.mjs');
    let id = 0;
    async function call(action, args, expectError) {
      const token = ++id;
      await receive({ data: { id: token, action, ...args } });
      assert.equal(last.id, token);
      if (expectError) {
        assert.match(last.error, expectError);
        return;
      }
      assert.equal(last.error, undefined);
      return last.data;
    }
    const make = (filename, content, method) => new File([
      zip([
        ['base.apk', zip([['assets/quest.txt', content, method]])],
        ['same.txt', 'identical'], ['duplicate.txt', 'one'], ['duplicate.txt', 'two']
      ])
    ], filename);
    const before = make('first.apks', 'quest=forest', 0);
    const after = make('second.apks', 'quest=desert', 8);
    await call('open', { file: before });
    const comparison = await call('compare', { file: after, nested: true, verifyPayloads: true });
    assert.equal(comparison.nested.groups[0].rows[0].canDiff, true);
    const result = await call('diff-entry', { scope: 1, entryName: 'assets/quest.txt' });
    assert.equal(result.previewOffset, 6);
    assert.equal(result.ranges[0].offset, 6);
    assert.deepEqual(result.source.archivePath, ['base.apk']);
    assert.equal(result.source.entry, 'assets/quest.txt');
    assert.equal(result.source.baseline.archive, 'first.apks');
    assert.equal(result.source.baseline.dataOffset, 30 + 'assets/quest.txt'.length);
    assert.equal(result.source.candidate.archive, 'second.apks');
    assert.equal(result.source.candidate.method, 8);
    assert.equal(await (await call('diff-entry-download', { side: 'before' })).text(), 'quest=forest');
    assert.equal(await (await call('diff-entry-download', { side: 'after' })).text(), 'quest=desert');
    const preview = await call('diff-preview', { offset: 6 });
    assert.equal(Buffer.from(preview.before).toString(), 'forest');
    assert.equal(Buffer.from(preview.after).toString(), 'desert');
    assert.deepEqual((await call('diff-bytes', { offset: 4 })).source, result.source);
    await call('diff-entry', { scope: 0, entryName: 'duplicate.txt' }, /duplicate/);
    await call('diff-entry', { scope: 1, entryName: 'Assets/quest.txt' }, /exact entry path/);
    await call('compare', { file: after, nested: false });
    await call('diff-entry-download', { side: 'after' }, /Open a ZIP entry pair/);
    const equal = await call('diff-entry', { scope: 0, entryName: 'same.txt' });
    assert.equal(equal.totalRanges, 0);
    const full = await call('full-report');
    const report = JSON.parse(await full.output.text());
    assert.ok(report.operations.some(op =>
      op.kind === 'byteDiff' && op.result.source?.entry === 'assets/quest.txt'));
    await call('open', { file: after });
    await call('diff-entry', { scope: 0, entryName: 'same.txt' }, /Compare two ZIP archives first/);
  } finally {
    delete globalThis.self;
  }
});

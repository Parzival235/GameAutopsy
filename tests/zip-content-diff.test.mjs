import assert from 'node:assert/strict';
import test from 'node:test';
import { compareArchives } from '../compare.mjs';
import { inspect } from '../archive-members.mjs';
import { compareNestedArchives } from '../nested-compare.mjs';
import { createPayloadComparison } from '../zip-content-diff.mjs';
import { zip } from './zip-fixture.mjs';

const inspectZip = (entries, name) => inspect(new Blob([zip(entries)]), name);

test('payload verification finds same-size, same-CRC differences and traverses a nested metadata match', async () => {
  const left = zip([['assets/data.txt', 'plumless']]);
  const right = zip([['assets/data.txt', 'buckeroo']]);
  const before = await inspectZip([['base.apk', left], ['copy.txt', 'identical']], 'before.apks');
  const after = await inspectZip([['base.apk', right], ['copy.txt', 'identical']], 'after.apks');
  const metadata = compareArchives(before.report, after.report);
  assert.equal(metadata.counts.matched, 2);
  assert.equal(metadata.rows.length, 0);
  const verify = createPayloadComparison();
  const result = compareArchives(before.report, after.report, await verify(before, after));
  const apk = result.rows.find(row => row.name === 'base.apk');
  assert.equal(apk.metadataStatus, 'matched');
  assert.equal(apk.status, 'payloadChanged');
  assert.equal(apk.payload.sameSizeAndCrc32, true);
  assert.equal(result.rows.find(row => row.name === 'copy.txt').payload.status, 'equal');
  assert.deepEqual(result.payloadCoverage.counts, {
    shared: 2, attempted: 2, equal: 1, different: 1, failed: 0,
    ambiguous: 0, unavailable: 0, sizeLimit: 0, budgetLimit: 0
  });
  const detail = await compareNestedArchives(before, after, result, undefined, verify);
  const [nested] = detail.groups;
  assert.deepEqual(nested.path, ['base.apk']);
  assert.deepEqual(nested.rows[0].payload, {
    status: 'different', firstDifference: 0, differingBytes: 8,
    beforeOnly: 0, afterOnly: 0, sameSizeAndCrc32: true
  });
});

test('payload verification preserves CRC failures and never asserts equality for duplicates', async () => {
  const original = zip([['entry', 'contents'], ['duplicate', 'first'], ['duplicate', 'second']]);
  const corrupt = Buffer.from(original);
  corrupt[30 + 'entry'.length] ^= 1;
  const before = await inspect(new Blob([original]), 'original.zip');
  const after = await inspect(new Blob([corrupt]), 'corrupt.zip');
  const checked = await createPayloadComparison()(before, after);
  const result = compareArchives(before.report, after.report, checked);
  const failure = result.rows.find(row => row.name === 'entry');
  assert.equal(failure.payload.status, 'failed');
  assert.match(failure.payload.reason, /CRC32/);
  assert.equal(result.rows.find(row => row.name === 'duplicate').status, 'ambiguous');
  assert.equal(result.payloadCoverage.counts.equal, 0);
  assert.equal(result.payloadCoverage.counts.ambiguous, 1);
  assert.equal(result.payloadCoverage.counts.failed, 1);
});

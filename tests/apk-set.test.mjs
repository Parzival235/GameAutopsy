import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { analyze } from '../formats.mjs';
import { inspectApkSet } from '../apk-set.mjs';
import { parseBundletoolToc } from '../bundletool-toc.mjs';
import { apk, toc } from './apk-fixture.mjs';
import { zip } from './zip-fixture.mjs';

const root = async (bytes, name = 'demo.apks') => {
  const blob = new Blob([bytes]);
  return { blob, report: await analyze(blob, name) };
};

test('APK set distinguishes version mismatch, missing dependency and matching manifests', async () => {
  const normal = [
    ['base.apk', apk({ requiredTypes: 'abi', isSplitRequired: true })],
    ['config.apk', apk({ split: 'config.arm64_v8a', types: 'abi', abi: 'arm64-v8a' })]
  ];
  const matched = await inspectApkSet(await root(zip(normal)), 'arm64-v8a');
  assert.deepEqual(matched.findings.filter(f => f.level === 'Error'), []);
  assert.deepEqual(matched.nativeFiles, [{ apk: 'config.apk', name: 'libil2cpp.so' }]);
  assert.equal(matched.items[0].manifest.longVersionCode, '4294967396');
  const broken = await inspectApkSet(await root(zip([
    normal[0], ['feature.apk', apk({ split: 'feature', codeMajor: 2, dep: 'required_feature', abi: 'x86' })]
  ])), 'arm64-v8a');
  const codes = broken.findings.map(f => f.code);
  for (const expected of ['versionMismatch', 'missingDependency', 'missingSplitType', 'abiUnavailable']) assert.ok(codes.includes(expected), codes);
});

test('APK set separates bundletool variants and cites missing TOC archive paths', async () => {
  const table = toc([
    [['splits/base-one.apk', ''], ['splits/abi.apk', 'config.arm64_v8a']],
    [['splits/base-two.apk', ''], ['splits/not-here.apk', 'feature']]
  ]);
  assert.equal(parseBundletoolToc(table).variants.length, 2);
  const result = await inspectApkSet(await root(zip([
    ['toc.pb', table],
    ['splits/base-one.apk', apk()],
    ['splits/abi.apk', apk({ split: 'config.arm64_v8a' })],
    ['splits/base-two.apk', apk({ code: 101 })]
  ])));
  assert.equal(result.source, 'bundletool toc.pb');
  assert.equal(result.groups.length, 2);
  assert.ok(!result.findings.some(f => f.code === 'multipleBases' || f.code === 'versionMismatch'));
  assert.ok(result.findings.some(f => f.code === 'missingArchiveMember' && f.path === 'splits/not-here.apk'));
  assert.throws(() => parseBundletoolToc(Uint8Array.from([10, 22])), /length/);
});

test('APK set fingerprints v2 and v3 records and marks differing declared certificates', async () => {
  // Small DER envelopes stand in for certificates. The parser compares the declared bytes.
  const first = Buffer.from([0x30, 3, 2, 1, 1]);
  const second = Buffer.from([0x30, 3, 2, 1, 2]);
  const result = await inspectApkSet(await root(zip([
    ['base.apk', apk({ cert: first })],
    ['split.apk', apk({ split: 'feature', cert: second })]
  ])));
  assert.equal(result.items[0].signing.schemes[0].signers[0].certificateSha256, createHash('sha256').update(first).digest('hex'));
  assert.ok(result.findings.some(f => f.code === 'signerMismatch'));
  const v3 = await inspectApkSet(await root(apk({ cert: first, v3: true }), 'single.apk'));
  assert.deepEqual(v3.items[0].signing.schemes[0].signers[0].sdk, { min: 28, max: 0x7fffffff });
});

test('XAPK inventory checks named split APKs without guessing from filenames', async () => {
  const manifest = JSON.stringify({ package_name: 'org.example.game', split_apks: [{ file: 'missing.apk' }] });
  const result = await inspectApkSet(await root(zip([['base.apk', apk()], ['manifest.json', manifest]]), 'game.xapk'));
  assert.equal(result.source, 'XAPK manifest + APK manifests');
  assert.ok(result.findings.some(f => f.path === 'missing.apk' && f.code === 'missingArchiveMember'));
});

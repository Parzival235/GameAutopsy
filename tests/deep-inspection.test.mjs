import assert from 'node:assert/strict';
import test from 'node:test';
import { analyze, openUnityMember, openZipMember } from '../formats.mjs';
import { checkZip, verifyZipPayloads } from '../zip-checks.mjs';
import { searchBytes } from '../byte-search.mjs';

const none = 0xffffffff;
const android = 'http://schemas.android.com/apk/res/android';

function xmlChunk(type, width, size) {
  const b = Buffer.alloc(size);
  b.writeUInt16LE(type);
  b.writeUInt16LE(width, 2);
  b.writeUInt32LE(size, 4);
  return b;
}

function manifestFile(utf8) {
  const strings = ['manifest', 'package', 'org.example.🐧', 'uses-sdk', 'targetSdkVersion', 'a', android, 'uses-permission', 'name', 'android.permission.INTERNET', ''];
  const values = strings.map(s => {
    const content = Buffer.from(s, utf8 ? 'utf8' : 'utf16le');
    const length = utf8 ? Buffer.from([s.length, content.length]) : Buffer.from([s.length, 0]);
    return Buffer.concat([length, content, Buffer.alloc(utf8 ? 1 : 2)]);
  });
  const start = 28 + strings.length * 4;
  const pool = xmlChunk(1, 28, start + values.reduce((sum, b) => sum + b.length, 0));
  pool.writeUInt32LE(strings.length, 8);
  pool.writeUInt32LE(utf8 ? 0x100 : 0, 16);
  pool.writeUInt32LE(start, 20);
  let position = start;
  for (const [i, value] of values.entries()) {
    pool.writeUInt32LE(position - start, 28 + i * 4);
    value.copy(pool, position);
    position += value.length;
  }
  const node = (type, size, first, second) => {
    const b = xmlChunk(type, 16, size);
    b.writeUInt32LE(7, 8);
    b.writeUInt32LE(none, 12);
    b.writeUInt32LE(first, 16);
    b.writeUInt32LE(second, 20);
    return b;
  };
  function element(name, attributes) {
    const b = node(0x102, 36 + attributes.length * 20, none, name);
    b.writeUInt16LE(20, 24);
    b.writeUInt16LE(20, 26);
    b.writeUInt16LE(attributes.length, 28);
    for (const [i, [namespace, key, type, value]] of attributes.entries()) {
      const at = 36 + i * 20;
      b.writeUInt32LE(namespace, at);
      b.writeUInt32LE(key, at + 4);
      b.writeUInt32LE(none, at + 8);
      b.writeUInt16LE(8, at + 12);
      b.writeUInt8(type, at + 15);
      b.writeUInt32LE(value, at + 16);
    }
    return b;
  }
  const map = xmlChunk(0x180, 8, 8 + strings.length * 4);
  map.writeUInt32LE(0x01010270, 8 + 4 * 4);
  map.writeUInt32LE(0x01010001, 8 + 10 * 4);
  const chunks = [
    pool, map, node(0x100, 24, 5, 6),
    element(0, [[none, 1, 3, 2], [6, 10, 18, 1]]),
    element(3, [[6, 4, 16, 35]]), node(0x103, 24, none, 3),
    element(7, [[6, 8, 3, 9]]), node(0x103, 24, none, 7),
    node(0x103, 24, none, 0), node(0x101, 24, 5, 6)
  ];
  const size = 8 + chunks.reduce((sum, b) => sum + b.length, 0);
  const head = xmlChunk(3, 8, 8);
  head.writeUInt32LE(size, 4);
  return Buffer.concat([head, ...chunks]);
}

test('AXML resolves UTF-8 and UTF-16LE, keeps resource IDs, and records exact attribute offsets', async () => {
  for (const utf8 of [true, false]) {
    const data = manifestFile(utf8);
    const result = await analyze(new Blob([data]), 'AndroidManifest.xml');
    assert.equal(result.status, 'ok', result.warnings.join(' '));
    assert.deepEqual(result.manifest, {
      package: 'org.example.🐧', targetSdkVersion: 35, permissions: ['android.permission.INTERNET']
    });
    const row = result.rows.find(r => r.name === 'uses-sdk @ a:targetSdkVersion');
    assert.equal(row.resourceId, '0x01010270');
    assert.equal(data.readUInt32LE(row.offset + 16), 35);
    assert.equal(result.rows.find(r => r.resourceId === '0x01010001').name, 'manifest @ a:[0x01010001]');
  }
});

test('AXML preserves parsed rows when later attribute records exceed their chunk', async () => {
  const data = manifestFile(true);
  const original = await analyze(new Blob([data]), 'AndroidManifest.xml');
  const element = original.rows.find(r => r.name === '<uses-sdk>');
  data.writeUInt16LE(100, element.offset + 28);
  const result = await analyze(new Blob([data]), 'AndroidManifest.xml');
  assert.equal(result.status, 'partial');
  assert.match(result.warnings[0], /exceeds its chunk/);
  assert.equal(result.manifest.package, 'org.example.🐧');
});

function signedApk({ flags = 0, corrupt = false, version = 0x7109871a, aligned = false, badPayload = false } = {}) {
  const name = Buffer.from('lib/arm64-v8a/libtest.so');
  const content = Buffer.from(badPayload ? 'hEllo' : 'hello');
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50);
  local.writeUInt16LE(flags, 6);
  local.writeUInt32LE(0x3610a686, 14);
  local.writeUInt32LE(content.length, 18);
  local.writeUInt32LE(content.length, 22);
  local.writeUInt16LE(name.length, 26);
  const padding = aligned ? 16384 - local.length - name.length : 0;
  local.writeUInt16LE(padding, 28);
  const block = Buffer.alloc(8 + 13 + 24);
  block.writeBigUInt64LE(BigInt(block.length - 8 - (corrupt ? 1 : 0)));
  block.writeBigUInt64LE(5n, 8);
  block.writeUInt32LE(version, 16);
  block.writeBigUInt64LE(BigInt(block.length - 8), block.length - 24);
  block.write('APK Sig Block 42', block.length - 16);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50);
  central.writeUInt16LE(flags, 8);
  central.writeUInt32LE(0x3610a686, 16);
  central.writeUInt32LE(content.length, 20);
  central.writeUInt32LE(content.length, 24);
  central.writeUInt16LE(name.length, 28);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length + name.length, 12);
  end.writeUInt32LE(local.length + name.length + padding + content.length + block.length, 16);
  return new Blob([local, name, Buffer.alloc(padding), content, block, central, name, end]);
}

test('APK layout checks signing IDs, local names and 16 KiB payload offsets', async () => {
  const unaligned = signedApk({ version: 0x1b93ad61 });
  const parsed = await analyze(unaligned, 'test.apk');
  const results = await checkZip(unaligned, parsed);
  assert.equal(results.localHeadersChecked, 1);
  assert.equal(results.signingBlock.pairs[0].name, 'APK v3.1');
  assert.ok(results.checks.some(f => /16 KiB/.test(f.message)));
  assert.equal(await (await openZipMember(unaligned, parsed.rows[0])).blob.text(), 'hello');

  const aligned = signedApk({ aligned: true });
  const clean = await checkZip(aligned, await analyze(aligned, 'test.apk'));
  assert.ok(clean.checks.every(f => f.status === 'Info'));
  const corrupt = signedApk({ corrupt: true });
  const damaged = await checkZip(corrupt, await analyze(corrupt, 'test.apk'));
  assert.ok(damaged.checks.some(f => f.status === 'Error' && f.name === 'APK signing block'));
});

test('ZIP verification distinguishes valid headers from a corrupt payload', async () => {
  const file = signedApk({ badPayload: true, aligned: true });
  const report = await analyze(file, 'damaged.apk');
  const checks = await checkZip(file, report);
  assert.equal(checks.localHeadersChecked, 1);
  const crc = await verifyZipPayloads(file, report);
  assert.equal(crc.attempted, 1);
  assert.equal(crc.verified, 0);
  assert.match(crc.checks[0].message, /CRC32/);
});

test('UnityFS opens a file across Raw and LZ4 blocks even when LZ4 sizes are equal', async () => {
  const raw = Buffer.from('0123456789');
  const matchingSize = Buffer.concat([
    Buffer.from([0x11]), Buffer.from('A'), Buffer.from([1, 0, 0xf0, 0]), Buffer.from('123456789012345')
  ]);
  const payload = new Blob([raw, matchingSize]);
  const report = { rows: [
    { kind: 'UnityFS block', streamOffset: 0, unpackedSize: 10, offset: 0, size: 10, flags: 0 },
    { kind: 'UnityFS block', streamOffset: 10, unpackedSize: 21, offset: 10, size: 21, flags: 2 }
  ] };
  assert.equal(await (await openUnityMember(payload, report, { streamOffset: 8, size: 11 })).text(), '89AAAAAA123');
  report.rows[1].flags = 4;
  await assert.rejects(openUnityMember(payload, report, { streamOffset: 8, size: 11 }), /unsupported compression/);
});

test('byte search preserves chunk-boundary matches and overlapping continuation', async () => {
  const chunk = 1024 * 1024;
  const data = Buffer.alloc(chunk + 20);
  Buffer.from([0xab, 0, 0xcd]).copy(data, chunk - 1);
  assert.deepEqual((await searchBytes(new Blob([data]), 'AB ?? CD', 'hex')).offsets, [chunk - 1]);
  const overlap = new Blob(['A'.repeat(250)]);
  const first = await searchBytes(overlap, 'AA', 'text');
  assert.equal(first.offsets.length, 200);
  assert.equal(first.next, 200);
  const rest = await searchBytes(overlap, 'AA', 'text', first.next);
  assert.equal(rest.offsets[0], 200);
  assert.equal(rest.offsets.at(-1), 248);
  assert.equal(rest.next, null);
  await assert.rejects(searchBytes(overlap, '?? ??', 'hex'), /fixed byte/);
});

test('ELF checks PT_LOAD alignment separately from ZIP payload alignment', async () => {
  const elf = Buffer.alloc(128);
  elf.write('\x7fELF');
  elf.set([2, 1, 1], 4);
  elf.writeUInt16LE(183, 18);
  elf.writeBigUInt64LE(64n, 32);
  elf.writeUInt16LE(64, 52);
  elf.writeUInt16LE(56, 54);
  elf.writeUInt16LE(1, 56);
  elf.writeUInt32LE(1, 64);
  elf.writeUInt32LE(5, 68);
  elf.writeBigUInt64LE(128n, 96);
  elf.writeBigUInt64LE(128n, 104);
  elf.writeBigUInt64LE(0x4000n, 112);
  assert.equal((await analyze(new Blob([elf]), 'libtest.so')).details['ELF LOAD 16 KiB alignment'], 'All inspected LOAD segments aligned');
  elf.writeBigUInt64LE(0x1000n, 112);
  assert.equal((await analyze(new Blob([elf]), 'libtest.so')).details['ELF LOAD 16 KiB alignment'], '1 below 16 KiB');
});

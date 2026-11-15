import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { analyze } from '../formats.mjs';
import { compareArchives } from '../compare.mjs';
import { compareNestedArchives } from '../nested-compare.mjs';

const bytes = Buffer.from('PCK resource');

function pack(version, { packFlags = 0, entryFlags = 0, invalidOffset = false } = {}) {
  const name = Buffer.from((version < 3 ? 'res://' : '') + 'levels/🐧.txt');
  const padded = (name.length + 3) & ~3;
  const modern = version >= 2;
  const endDirectory = version >= 3;
  const entry = Buffer.alloc(4 + padded + (modern ? 36 : 32));
  const base = endDirectory ? 96 : modern ? 96 + 4 + entry.length : 0;
  const offset = modern ? base : 84 + 4 + entry.length;
  const directory = endDirectory ? offset + bytes.length : modern ? 96 : 84;
  const data = Buffer.alloc(Math.max(offset + bytes.length, directory + 4 + entry.length));
  data.write('GDPC');
  data.writeUInt32LE(version, 4);
  data.writeUInt32LE(modern ? 4 : 3, 8);
  if (modern) {
    data.writeUInt32LE(packFlags, 20);
    data.writeBigUInt64LE(BigInt(base), 24);
  }
  if (endDirectory) data.writeBigUInt64LE(BigInt(directory), 32);
  data.writeUInt32LE(1, directory);
  entry.writeUInt32LE(padded);
  name.copy(entry, 4);
  entry.writeBigUInt64LE(invalidOffset ? 0xffffffffffffffffn : BigInt(offset - base), 4 + padded);
  entry.writeBigUInt64LE(BigInt(bytes.length), 12 + padded);
  createHash('md5').update(bytes).digest().copy(entry, 20 + padded);
  if (modern) entry.writeUInt32LE(entryFlags, 36 + padded);
  entry.copy(data, directory + 4);
  bytes.copy(data, offset);
  return { blob: new Blob([data]), offset, name: name.toString() };
}

test('standalone PCK versions 0–4 report physical offsets and declared MD5', async () => {
  for (const version of [0, 1, 2, 3, 4]) {
    const { blob, offset, name } = pack(version);
    const report = await analyze(blob, 'game.pck');
    assert.equal(report.status, 'ok', report.warnings);
    const row = report.rows.find(entry => entry.open);
    assert.equal(row.name, name);
    assert.equal(row.offset, offset);
    assert.notEqual(row.recordOffset, row.offset);
    assert.equal(row.declaredMd5, createHash('md5').update(bytes).digest('hex'));
    assert.equal(await blob.slice(row.offset, row.offset + row.size).text(), bytes.toString());
  }
});

test('PCK special entries keep metadata and invalid ranges cannot be opened', async () => {
  for (const [flags, kind] of [[1, 'PCK encrypted file'], [2, 'PCK removal'], [4, 'PCK delta file']]) {
    const { blob } = pack(4, { entryFlags: flags });
    const report = await analyze(blob, 'game.pck');
    assert.equal(report.rows.at(-1).kind, kind);
    assert.equal(report.rows.at(-1).open, false);
    assert.equal(report.rows.at(-1).offset, null);
  }
  const encrypted = await analyze(pack(3, { packFlags: 1 }).blob, 'game.pck');
  assert.equal(encrypted.rows.length, 1);
  assert.match(encrypted.warnings[0], /encryption/);
  const damaged = await analyze(pack(3, { invalidOffset: true }).blob, 'game.pck');
  assert.equal(damaged.rows.at(-1).open, false);
  assert.match(damaged.warnings[0], /outside/);
  const format = pack(3);
  const truncated = await analyze(format.blob.slice(0, -1), 'game.pck');
  assert.equal(truncated.status, 'partial');
});

function zipCrc(contents) {
  let crc = -1;
  for (const byte of contents) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ -1) >>> 0;
}

function zip(entries) {
  const body = [];
  const directory = [];
  let start = 0;
  for (const [path, value] of entries) {
    const data = Buffer.from(value);
    const name = Buffer.from(path);
    const crc = zipCrc(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(start, 42);
    body.push(local, name, data);
    directory.push(central, name);
    start += local.length + name.length + data.length;
  }
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.reduce((sum, part) => sum + part.length, 0), 12);
  end.writeUInt32LE(start, 16);
  return Buffer.concat([...body, ...directory, end]);
}

const inspectZip = async (data, name) => {
  const blob = new Blob([data]);
  return { blob, report: await analyze(blob, name) };
};

test('nested archive comparison separates scopes and reports bad or unpaired inputs', async () => {
  const old = zip([['base.apk', zip([['assets/level.zip', zip([['map.json', '{}']])]])],
    ['broken.apk', 'old'],
    ['same.apk', zip([['a.txt', 'same']])]]);
  const next = zip([['base.apk', zip([['assets/level.zip', zip([['map.json', '{"id":1}']])]])],
    ['broken.apk', 'new'],
    ['same.apk', zip([['a.txt', 'same']])],
    ['extra.apk', zip([['b.txt', 'new']])]]);
  const before = await inspectZip(old, 'old.apks');
  const after = await inspectZip(next, 'new.apks');
  const top = compareArchives(before.report, after.report);
  const result = await compareNestedArchives(before, after, top);
  assert.deepEqual(result.groups.map(group => group.path), [['base.apk'], ['base.apk', 'assets/level.zip']]);
  assert.equal(result.groups[1].rows[0].name, 'map.json');
  assert.equal(result.groups[1].counts.changed, 1);
  assert.equal(result.matchingArchives, 1);
  assert.equal(result.skipped, 2);
  assert.equal(result.notices.find(item => item.path[0] === 'extra.apk').reason, 'Archive path is present on only one side.');
  assert.match(result.notices.find(item => item.path[0] === 'broken.apk').reason, /complete ZIP directories/);
});

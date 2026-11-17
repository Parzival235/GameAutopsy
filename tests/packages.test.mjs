import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { analyze } from '../formats.mjs';
import { buildInventory } from '../inventory.mjs';
import { zip } from './zip-fixture.mjs';
import { openMember } from '../archive-members.mjs';
import { compareArchives } from '../compare.mjs';
import { compareNestedArchives } from '../nested-compare.mjs';
import { exportInventory } from '../inventory-export.mjs';

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

test('inventory indexes mixed containers and preserves exact open routes', async () => {
  const pck = pack(3);
  const root = await inspectZip(zip([
    ['base.apk', zip([['assets/game.pck', Buffer.from(await pck.blob.arrayBuffer())], ['assets/broken.bundle', 'bogus']])],
    ['config.apk', zip([['android.json', 'other']])]
  ]), 'root.apks');
  const result = await buildInventory(root);
  assert.equal(result.containers, 4);
  assert.equal(result.skipped, 1);
  assert.equal(result.notices[0].path.at(-1), 'assets/broken.bundle');
  const hit = result.rows.find(row => row.name === pck.name);
  assert.equal(hit.category, 'Text / data');
  assert.deepEqual(hit.path, ['root.apks', 'base.apk', 'assets/game.pck']);
  let location = root;
  for (const index of hit.route) location = await openMember(location, location.report.rows[index]);
  assert.equal(await location.blob.text(), bytes.toString());
  assert.equal(location.report.source.dataOffset, pck.offset);

  const { output, manifest } = await exportInventory(root, result, [hit.id]);
  assert.equal(manifest.skipped.length, 0);
  const [entry] = manifest.entries;
  assert.equal(entry.containerFormat, 'Godot PCK');
  assert.deepEqual(entry.path, [...hit.path, hit.name]);
  assert.match(entry.output, /^files\/archive-0-0\/levels\//);
  assert.equal(entry.verification, 'decodedSize');
  assert.equal(entry.source.dataOffset, pck.offset);
  const exported = { blob: output, report: await analyze(output, 'selection.zip') };
  const saved = await openMember(exported, exported.report.rows.find(row => row.name === entry.output));
  assert.equal(await saved.blob.text(), bytes.toString());
});

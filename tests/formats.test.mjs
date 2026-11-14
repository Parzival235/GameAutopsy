import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import { analyze, openZipMember, preview, sampleStrings } from '../formats.mjs';

function makeZip({ deflate = false, zip64 = false, badCrc = false } = {}) {
  const data = Buffer.from('hello');
  const packed = deflate ? deflateRawSync(data) : data;
  const name = Buffer.from('hello.txt');
  const crc = badCrc ? 0 : 0x3610a686;
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(deflate ? 8 : 0, 8);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(packed.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(name.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(deflate ? 8 : 0, 10);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(zip64 ? 0xffffffff : packed.length, 20);
  central.writeUInt32LE(zip64 ? 0xffffffff : data.length, 24);
  central.writeUInt16LE(name.length, 28);
  const extra = Buffer.alloc(zip64 ? 20 : 0);
  if (zip64) {
    central.writeUInt16LE(extra.length, 30);
    extra.writeUInt16LE(1, 0);
    extra.writeUInt16LE(16, 2);
    extra.writeBigUInt64LE(BigInt(data.length), 4);
    extra.writeBigUInt64LE(BigInt(packed.length), 12);
  }
  const centralOffset = local.length + name.length + packed.length;
  const centralSize = central.length + name.length + extra.length;
  const record = Buffer.alloc(zip64 ? 76 : 0);
  if (zip64) {
    record.writeUInt32LE(0x06064b50, 0);
    record.writeBigUInt64LE(44n, 4);
    record.writeBigUInt64LE(1n, 24);
    record.writeBigUInt64LE(1n, 32);
    record.writeBigUInt64LE(BigInt(centralSize), 40);
    record.writeBigUInt64LE(BigInt(centralOffset), 48);
    record.writeUInt32LE(0x07064b50, 56);
    record.writeBigUInt64LE(BigInt(centralOffset + centralSize), 64);
    record.writeUInt32LE(1, 72);
  }
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(zip64 ? 65535 : 1, 8);
  end.writeUInt16LE(zip64 ? 65535 : 1, 10);
  end.writeUInt32LE(zip64 ? 0xffffffff : centralSize, 12);
  end.writeUInt32LE(zip64 ? 0xffffffff : centralOffset, 16);
  return new Blob([local, name, packed, central, name, extra, record, end]);
}

test('ZIP Stored, Deflate and ZIP64 preserve offsets and verified bytes', async () => {
  for (const options of [{}, { deflate: true }, { deflate: true, zip64: true }]) {
    const file = makeZip(options);
    const report = await analyze(file, 'sample.apk');
    assert.equal(report.status, 'ok');
    assert.equal(report.rows.length, 1);
    assert.equal(report.rows[0].offset, 0);
    assert.equal(report.rows[0].size, 5);
    assert.equal(report.details.ZIP64, options.zip64 ? 'Có' : 'Không');
    const result = await openZipMember(file, report.rows[0]);
    assert.equal(result.dataOffset, 39);
    assert.equal(await result.blob.text(), 'hello');
  }
});

test('ZIP verifies integrity and reports a malformed directory', async () => {
  const file = makeZip({ badCrc: true });
  const report = await analyze(file, 'bad.apks');
  await assert.rejects(openZipMember(file, report.rows[0]), /CRC32/);
  const truncated = await analyze(file.slice(0, -1), 'bad.apks');
  assert.equal(truncated.status, 'partial');
  assert.match(truncated.warnings[0], /EOCD/);
});

test('DEX maps structural offsets and rejects out-of-range table data', async () => {
  const dex = Buffer.alloc(144);
  dex.write('dex\n035\0');
  dex.writeUInt32LE(dex.length, 32);
  dex.writeUInt32LE(112, 36);
  dex.writeUInt32LE(0x12345678, 40);
  dex.writeUInt32LE(120, 52);
  dex.writeUInt32LE(2, 56);
  dex.writeUInt32LE(112, 60);
  dex.writeUInt32LE(1, 120);
  dex.writeUInt16LE(0x2002, 124);
  dex.writeUInt32LE(2, 128);
  dex.writeUInt32LE(136, 132);
  const report = await analyze(new Blob([dex]), 'classes.dex');
  assert.deepEqual(report.rows.map(e => [e.name, e.offset]), [
    ['header', 0], ['string IDs', 112], ['string data', 136]
  ]);
  dex.writeUInt32LE(1000, 60);
  assert.equal((await analyze(new Blob([dex]), 'classes.dex')).status, 'partial');
});

test('ELF section names and file offsets are read from the section table', async () => {
  const elf = Buffer.alloc(215);
  elf.write('\x7fELF');
  elf[4] = 2;
  elf[5] = 1;
  elf[6] = 1;
  elf.writeUInt16LE(62, 18);
  elf.writeBigUInt64LE(64n, 40);
  elf.writeUInt16LE(64, 52);
  elf.writeUInt16LE(64, 58);
  elf.writeUInt16LE(2, 60);
  elf.writeUInt16LE(1, 62);
  elf.writeUInt32LE(1, 128);
  elf.writeUInt32LE(3, 132);
  elf.writeBigUInt64LE(192n, 152);
  elf.writeBigUInt64LE(11n, 160);
  elf.write('\0.shstrtab\0', 192);
  const report = await analyze(new Blob([elf]), 'game.so');
  assert.equal(report.details['Kiến trúc'], 'x86-64');
  assert.equal(report.rows[1].name, '.shstrtab');
  assert.equal(report.rows[1].offset, 192);
});

test('hex handles empty files and string scanning finds both encodings', async () => {
  assert.deepEqual(await preview(new Blob(), 0), { offset: 0, bytes: [] });
  const content = new Blob([Buffer.from('sample\0\0\0'), Buffer.from('second', 'utf16le')]);
  const { rows } = await sampleStrings(content);
  assert.deepEqual(rows.map(({ offset, encoding, text }) => [offset, encoding, text]), [
    [0, 'ASCII', 'sample'], [9, 'UTF-16LE', 'second']
  ]);
});

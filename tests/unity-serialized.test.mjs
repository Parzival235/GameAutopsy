import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect, openMember } from '../archive-members.mjs';
import { analyze } from '../formats.mjs';
import { decodeUnityLzma } from '../unity-lzma.mjs';

const pathId = -9223372036854770000n;

function serialized({
  version = 22, endian = 'LE', payloadOffset = 0, typeIndex = 0, duplicate = false, typeTrees = true,
  extracted = false, engine = '6000.0.65f1'
} = {}) {
  const extended = version >= 22;
  const header = Buffer.alloc(extended ? 48 : 20);
  const metadata = Buffer.alloc(4096);
  let position = 0;
  const string = text => { position += metadata.write(text + '\0', position); };
  const integer = (method, value) => { position = metadata[method + endian](value, position); };
  const align = () => { position = (position + 3) & ~3; };
  const byte = value => { metadata[position++] = value; };
  string(engine);
  integer('writeInt32', 13); // Android
  byte(Number(typeTrees));
  integer('writeInt32', 1); // one serialized type
  integer('writeInt32', 114);
  byte(0); // stripped
  integer('writeInt16', 0);
  position += 32; // script ID and type hash
  if (typeTrees) {
    if (version >= 23) {
      position += 16; // content hash
      integer('writeUInt32', extracted ? 0 : 16);
      if (!extracted) position += 16; // length-delimited inline tree
    } else {
      integer('writeInt32', 1); // tree node
      integer('writeInt32', 4); // string bytes
      position += (version >= 19 ? 32 : 24) + 4;
    }
    if (version >= 21) {
      integer('writeInt32', 0); // type dependencies
    }
  }
  integer('writeInt32', duplicate ? 2 : 1);
  for (let i = 0; i < (duplicate ? 2 : 1); i++) {
    align();
    integer('writeBigInt64', pathId);
    if (extended) integer('writeBigInt64', BigInt(payloadOffset));
    else integer('writeUInt32', payloadOffset);
    integer('writeUInt32', 4);
    integer('writeInt32', typeIndex);
  }
  integer('writeInt32', 2); // local script references
  for (let index = 0; index < 2; index++) {
    integer('writeInt32', 0);
    align();
    integer('writeBigInt64', 12n + BigInt(index));
  }
  integer('writeInt32', 1);
  string('');
  metadata.fill(0xab, position, position + 16);
  position += 16;
  integer('writeInt32', 2);
  string('archive:/CAB-other/CAB-other');
  if (version >= 20) integer('writeInt32', 0); // managed reference types
  if (version >= 26) integer('writeInt32', 0); // shared subtrees
  string('');
  const dataOffset = (header.length + position + 15) & ~15;
  const payload = Buffer.from([0x41, 0x42, 0x43, 0x44]);
  const size = dataOffset + payload.length;
  header.writeUInt32BE(version, 8);
  header[16] = Number(endian === 'BE');
  if (extended) {
    header.writeUInt32BE(position, 20);
    header.writeBigUInt64BE(BigInt(size), 24);
    header.writeBigUInt64BE(BigInt(dataOffset), 32);
  } else {
    header.writeUInt32BE(position, 0);
    header.writeUInt32BE(size, 4);
    header.writeUInt32BE(dataOffset, 12);
  }
  return new Blob([header, metadata.subarray(0, position), Buffer.alloc(dataOffset - header.length - position), payload]);
}

test('Unity serialized objects preserve signed Path IDs, class, record and payload offsets', async () => {
  for (const options of [
    { version: 17, endian: 'BE' }, { version: 22 }, { version: 22, typeTrees: false, engine: '6000.0.65f1\n2' },
    { version: 23, extracted: true }, { version: 26 }
  ]) {
    const file = await inspect(serialized(options), 'level0');
    const { report } = file;
    assert.equal(report.format, 'Unity serialized file');
    assert.equal(report.status, 'ok', report.warnings);
    const [object] = report.rows.filter(row => row.kind === 'Unity object');
    assert.equal(object.pathId, String(pathId));
    assert.equal(object.className, 'MonoBehaviour');
    assert.equal(object.offset, report.details['Object data offset']);
    assert.equal(object.recordSize, options.version >= 22 ? 24 : 20);
    assert.equal(report.details['Script references'], 2);
    assert.equal(report.details['Unity engine version'], '6000.0.65f1');
    assert.deepEqual(report.unitySerialized.classes, [{ classId: 114, className: 'MonoBehaviour', count: 1 }]);
    assert.deepEqual(report.unitySerialized.externals, [
      { fileId: 1, path: 'archive:/CAB-other/CAB-other', guid: 'ab'.repeat(16), referenceType: 2 }
    ]);
    if (options.version >= 23) assert.equal(object.inlineTypeTree, !options.extracted);
    assert.equal(await (await openMember(file, object)).blob.text(), 'ABCD');
    assert.doesNotThrow(() => JSON.stringify(report));
  }
});

test('Unity serialized metadata rejects invalid ranges, retains duplicate IDs and reports truncation', async () => {
  const blob = serialized({ duplicate: true, payloadOffset: -1, typeIndex: 64 });
  const result = await analyze(blob, 'broken.assets');
  assert.equal(result.status, 'partial');
  const objects = result.rows.filter(row => row.kind === 'Unity object');
  assert.equal(objects.length, 2);
  assert.ok(objects.every(row => row.offset === null && !row.open && row.classId === null));
  for (const warning of [/reuse a Path ID/, /invalid type index/, /outside/]) assert.match(result.warnings.join('\n'), warning);
  const truncated = await analyze(blob.slice(0, 120), 'broken.assets');
  assert.equal(truncated.format, 'Unity serialized file');
  assert.match(truncated.warnings.join('\n'), /truncated/);
  assert.equal((await analyze(new Blob([new Uint8Array(1024)]), 'fake.assets')).format, 'Binary');
});

// Generated with Python's lzma.FORMAT_RAW and prefixed with the five UnityFS LZMA properties.
const block = Buffer.from('XQAAEAAAKpuJJ3hgXcR+Zd/0J4uPFynfGdN5nk971qhX/OIdc///wmIAAA==', 'base64');
const directory = Buffer.from('XQAAEAAAAGbaZ5A0QA9SSDkNLDTybB7SN+hAzteWBE83Wyzt///9FzAA', 'base64');

test('UnityFS decodes LZMA directories and members with bounded input and output', async () => {
  const header = Buffer.alloc(64);
  header.write('UnityFS\0');
  header.writeUInt32BE(7, 8);
  header.write('5.x.x\0' + '2021.3.10f1\0', 12);
  header.writeBigUInt64BE(BigInt(header.length + directory.length + block.length), 30);
  header.writeUInt32BE(directory.length, 38);
  header.writeUInt32BE(63, 42);
  header.writeUInt32BE(0x41, 46);
  const file = await inspect(new Blob([header, directory, block]), 'fixture.bundle');
  const { report } = file;
  assert.equal(report.status, 'ok', report.warnings);
  assert.equal(report.details['Directory compression'], 'LZMA');
  assert.equal(report.rows.at(-1).name, 'CAB-test');
  const member = await openMember(file, report.rows.at(-1));
  assert.equal(await member.blob.text(), 'Unity object bytes '.repeat(50));
  assert.throws(() => decodeUnityLzma(block.subarray(0, -12), 950), /truncated|invalid match/);
  assert.throws(() => decodeUnityLzma(block, 949), /declared size|invalid match/);
  assert.throws(() => decodeUnityLzma(block, 32 * 1024 * 1024 + 1), /block limit/);
});

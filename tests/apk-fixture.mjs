import { zip } from './zip-fixture.mjs';

const android = 'http://schemas.android.com/apk/res/android';
const none = 0xffffffff;
export const packageName = 'org.example.game';

function chunk(type, header, length) {
  const b = Buffer.alloc(length);
  b.writeUInt16LE(type);
  b.writeUInt16LE(header, 2);
  b.writeUInt32LE(length, 4);
  return b;
}

function manifest({ split, packageId = packageName, code = 100, codeMajor = 1, configForSplit, dep, isSplitRequired = false, types, requiredTypes }) {
  const names = ['android', android, 'manifest', 'uses-split', 'name'];
  const id = str => {
    if (!names.includes(str)) names.push(str);
    return names.indexOf(str);
  };
  const attr = (ns, name, type, value) => [ns, id(name), type, type === 3 ? id(value) : value];
  const a = (name, type, value) => attr(1, name, type, value);
  const root = [attr(none, 'package', 3, packageId), a('versionCode', 16, code), a('versionCodeMajor', 16, codeMajor)];
  if (split) root.push(attr(none, 'split', 3, split));
  if (configForSplit) root.push(attr(none, 'configForSplit', 3, configForSplit));
  if (isSplitRequired) root.push(a('isSplitRequired', 18, 1));
  if (types) root.push(a('splitTypes', 3, types));
  if (requiredTypes) root.push(a('requiredSplitTypes', 3, requiredTypes));
  const child = dep ? [a('name', 3, dep)] : [];

  const values = names.map(text => {
    const bytes = Buffer.from(text);
    return Buffer.concat([Buffer.from([text.length, bytes.length]), bytes, Buffer.alloc(1)]);
  });
  const dataStart = 28 + names.length * 4;
  const pool = chunk(1, 28, dataStart + values.reduce((sum, value) => sum + value.length, 0));
  pool.writeUInt32LE(names.length, 8);
  pool.writeUInt32LE(0x100, 16);
  pool.writeUInt32LE(dataStart, 20);
  let cursor = dataStart;
  values.forEach((value, i) => {
    pool.writeUInt32LE(cursor - dataStart, 28 + i * 4);
    value.copy(pool, cursor);
    cursor += value.length;
  });
  const simple = (type, first, second, size = 24) => {
    const b = chunk(type, 16, size);
    b.writeUInt32LE(none, 12);
    b.writeUInt32LE(first, 16);
    b.writeUInt32LE(second, 20);
    return b;
  };
  const element = (index, attrs) => {
    const b = simple(0x102, none, index, 36 + attrs.length * 20);
    b.writeUInt16LE(20, 24);
    b.writeUInt16LE(20, 26);
    b.writeUInt16LE(attrs.length, 28);
    attrs.forEach(([ns, name, type, value], i) => {
      const at = 36 + i * 20;
      b.writeUInt32LE(ns, at);
      b.writeUInt32LE(name, at + 4);
      b.writeUInt32LE(none, at + 8);
      b.writeUInt16LE(8, at + 12);
      b.writeUInt8(type, at + 15);
      b.writeUInt32LE(value, at + 16);
    });
    return b;
  };
  const chunks = [pool, simple(0x100, 0, 1), element(2, root)];
  if (child.length) chunks.push(element(3, child), simple(0x103, none, 3));
  chunks.push(simple(0x103, none, 2), simple(0x101, 0, 1));
  const header = chunk(3, 8, 8);
  header.writeUInt32LE(8 + chunks.reduce((sum, b) => sum + b.length, 0), 4);
  return Buffer.concat([header, ...chunks]);
}

const u32 = n => {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(n);
  return buffer;
};
const lp = buffer => Buffer.concat([u32(buffer.length), buffer]);

function addSigningBlock(archive, leaf, v3) {
  const sdk = v3 ? Buffer.concat([u32(28), u32(0x7fffffff)]) : Buffer.alloc(0);
  const empty = lp(Buffer.alloc(0));
  const data = Buffer.concat([empty, lp(lp(leaf)), sdk, empty, ...(!v3 ? [empty] : [])]);
  const pair = lp(lp(Buffer.concat([lp(data), sdk, empty, empty])));
  const signing = Buffer.alloc(8 + 12 + pair.length + 24);
  signing.writeBigUInt64LE(BigInt(signing.length - 8));
  signing.writeBigUInt64LE(BigInt(pair.length + 4), 8);
  signing.writeUInt32LE(v3 ? 0xf05368c0 : 0x7109871a, 16);
  pair.copy(signing, 20);
  signing.writeBigUInt64LE(BigInt(signing.length - 8), signing.length - 24);
  signing.write('APK Sig Block 42', signing.length - 16);
  const directory = archive.readUInt32LE(archive.length - 6);
  archive.writeUInt32LE(directory + signing.length, archive.length - 6);
  return Buffer.concat([archive.subarray(0, directory), signing, archive.subarray(directory)]);
}

export function apk(options = {}) {
  const entries = [['AndroidManifest.xml', manifest(options)]];
  if (options.abi) entries.push(['lib/' + options.abi + '/libil2cpp.so', 'test library']);
  const archive = zip(entries);
  return options.cert ? addSigningBlock(archive, options.cert, options.v3) : archive;
}

const varint = n => {
  const bytes = [];
  while (n > 127) { bytes.push((n & 127) | 128); n >>>= 7; }
  bytes.push(n);
  return Buffer.from(bytes);
};
const message = (field, value) => {
  const bytes = Buffer.from(value);
  return Buffer.concat([varint(field * 8 + 2), varint(bytes.length), bytes]);
};
const scalar = (field, value) => Buffer.concat([varint(field * 8), varint(value)]);
export function toc(groups) {
  const variants = groups.map((items, index) => {
    const descriptions = items.map(([path, split]) => message(2, Buffer.concat([
      message(2, path), message(3, Buffer.concat([message(1, split), scalar(2, split ? 0 : 1)]))
    ])));
    const module = message(2, Buffer.concat([message(1, message(1, 'base')), ...descriptions]));
    return message(1, Buffer.concat([module, scalar(3, index)]));
  });
  return Buffer.concat([message(4, packageName), ...variants]);
}

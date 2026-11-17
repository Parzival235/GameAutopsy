// Small synthetic files. Both examples go through the regular worker readers.
const encoder = new TextEncoder();
const encode = text => encoder.encode(text);
const cString = text => encode(text + '\0');

function record(size, write) {
  const buffer = new ArrayBuffer(size);
  write(new DataView(buffer));
  return new Uint8Array(buffer);
}

function int32(value) {
  return record(4, view => view.setInt32(0, value, true));
}

function unityFile(name, objects, move) {
  const strings = cString('GameObject\0Base\0unsigned int\0m_Layer');
  const tree = record(64, view => {
    view.setInt32(12, -1, true);
    view.setUint32(8, 11, true); // Base
    view.setUint8(34, 1); // Child depth
    view.setUint32(36, 16, true); // unsigned int
    view.setUint32(40, 29, true); // m_Layer
    view.setInt32(44, 4, true);
  });
  const metadata = [
    cString('2022.1.20f1'), int32(13), Uint8Array.of(1), // Embedded TypeTrees
    int32(1), int32(1), Uint8Array.of(0, 255, 255), new Uint8Array(16),
    int32(2), int32(strings.length), tree, strings, int32(0), int32(objects.length)
  ];
  const start = metadata.reduce((sum, part) => sum + part.length, 0);
  metadata.push(new Uint8Array((4 - start % 4) % 4));
  for (const [index, [id]] of objects.entries()) {
    metadata.push(record(24, view => {
      view.setBigInt64(0, BigInt(id), true);
      view.setBigInt64(8, BigInt(index * 4), true);
      view.setUint32(16, 4, true);
    }));
  }
  metadata.push(int32(0), int32(0), int32(0), cString(''));
  const metadataSize = metadata.reduce((sum, part) => sum + part.length, 0);
  const dataOffset = Math.ceil((48 + metadataSize) / 16) * 16 + move;
  const header = record(48, view => {
    view.setUint32(8, 22);
    view.setUint32(20, metadataSize);
    view.setBigUint64(24, BigInt(dataOffset + objects.length * 4));
    view.setBigUint64(32, BigInt(dataOffset));
  });
  return new File([header, ...metadata, new Uint8Array(dataOffset - 48 - metadataSize),
    ...objects.map(([, layer]) => int32(layer))], name);
}

export function demoUnity() {
  return [
    unityFile('demo-before.assets', [[3, 0], [5, 2], [8, 1]], 0),
    unityFile('demo-after.assets', [[3, 7], [5, 2], [11, 4]], 32)
  ];
}

function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ (value & 1 ? 0xedb88320 : 0);
  }
  return (value ^ 0xffffffff) >>> 0;
}

function zip(entries) {
  const data = [];
  const directory = [];
  let offset = 0;
  for (const [path, contents] of entries) {
    const name = encode(path);
    const crc = crc32(contents);
    const local = record(30, view => {
      view.setUint32(0, 0x04034b50, true);
      view.setUint16(4, 20, true);
      view.setUint32(14, crc, true);
      view.setUint32(18, contents.length, true);
      view.setUint32(22, contents.length, true);
      view.setUint16(26, name.length, true);
    });
    const central = record(46, view => {
      view.setUint32(0, 0x02014b50, true);
      view.setUint16(4, 20, true);
      view.setUint16(6, 20, true);
      view.setUint32(16, crc, true);
      view.setUint32(20, contents.length, true);
      view.setUint32(24, contents.length, true);
      view.setUint16(28, name.length, true);
      view.setUint32(42, offset, true);
    });
    data.push(local, name, contents);
    directory.push(central, name);
    offset += local.length + name.length + contents.length;
  }
  const end = record(22, view => {
    view.setUint32(0, 0x06054b50, true);
    view.setUint16(8, entries.length, true);
    view.setUint16(10, entries.length, true);
    view.setUint32(12, directory.reduce((sum, part) => sum + part.length, 0), true);
    view.setUint32(16, offset, true);
  });
  const result = new Uint8Array(offset + directory.reduce((sum, part) => sum + part.length, 0) + end.length);
  let position = 0;
  for (const part of [...data, ...directory, end]) {
    result.set(part, position);
    position += part.length;
  }
  return result;
}

export function demoArchive() {
  return ['before', 'after'].map((version, index) => {
    const nested = zip([
      ['settings.json', encode(JSON.stringify({ maxLives: index ? 7 : 3 }))],
      ['readme.txt', encode('Synthetic GameAutopsy demo data.')]
    ]);
    return new File([zip([
      ['assets/config.zip', nested],
      [index ? 'assets/new-map.txt' : 'assets/old-map.txt', encode('Demo map')]
    ])], 'demo-' + version + '.zip');
  });
}

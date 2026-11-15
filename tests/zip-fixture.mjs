import { deflateRawSync } from 'node:zlib';

function zipCrc(contents) {
  let crc = -1;
  for (const byte of contents) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ -1) >>> 0;
}

export function zip(entries) {
  const body = [];
  const directory = [];
  let start = 0;
  for (const [path, value, method = 0] of entries) {
    const data = Buffer.from(value);
    const packed = method === 8 ? deflateRawSync(data) : data;
    const name = Buffer.from(path);
    const crc = zipCrc(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(packed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(start, 42);
    body.push(local, name, packed);
    directory.push(central, name);
    start += local.length + name.length + packed.length;
  }
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.reduce((sum, part) => sum + part.length, 0), 12);
  end.writeUInt32LE(start, 16);
  return Buffer.concat([...body, ...directory, end]);
}

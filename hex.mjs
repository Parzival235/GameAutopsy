export function interpretBytes(bytes, little) {
  const data = new DataView(Uint8Array.from(bytes.slice(0, 8)).buffer);
  const read = (width, method) => data.byteLength >= width ? data[method](0, little) : '—';
  return {
    'u8': read(1, 'getUint8'), 'i8': read(1, 'getInt8'),
    'u16': read(2, 'getUint16'), 'i16': read(2, 'getInt16'),
    'u32': read(4, 'getUint32'), 'i32': read(4, 'getInt32'),
    'u64': read(8, 'getBigUint64'), 'i64': read(8, 'getBigInt64'),
    'f32': read(4, 'getFloat32'), 'f64': read(8, 'getFloat64')
  };
}

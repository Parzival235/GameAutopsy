const encoder = new TextEncoder();

function header(length, signature) {
  const bytes = new Uint8Array(length);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, signature, true);
  return { bytes, view };
}

// Assemble a ZIP of already-checked payloads. Blob parts avoid a full ZIP-sized buffer.
export function storedZip(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  let centralSize = 0;
  if (entries.length >= 0xffff) throw new Error('Too many entries for a ZIP32 export.');
  for (const { name, blob, crc32 } of entries) {
    const path = encoder.encode(name);
    if (path.length > 0xffff || blob.size >= 0xffffffff) throw new Error('An export entry exceeds ZIP32 limits.');
    const local = header(30, 0x04034b50);
    local.view.setUint16(4, 20, true);
    local.view.setUint16(6, 0x800, true); // UTF-8 names
    local.view.setUint16(12, 0x21, true); // 1980-01-01
    local.view.setUint32(14, crc32, true);
    local.view.setUint32(18, blob.size, true);
    local.view.setUint32(22, blob.size, true);
    local.view.setUint16(26, path.length, true);
    const central = header(46, 0x02014b50);
    central.view.setUint16(4, 20, true);
    central.bytes.set(local.bytes.subarray(4, 28), 6);
    central.view.setUint32(42, offset, true);
    localParts.push(local.bytes, path, blob);
    centralParts.push(central.bytes, path);
    offset += local.bytes.length + path.length + blob.size;
    centralSize += central.bytes.length + path.length;
    if (offset + centralSize + 22 >= 0xffffffff) throw new Error('The archive exceeds the ZIP32 export limit.');
  }
  const end = header(22, 0x06054b50);
  end.view.setUint16(8, entries.length, true);
  end.view.setUint16(10, entries.length, true);
  end.view.setUint32(12, centralSize, true);
  end.view.setUint32(16, offset, true);
  return new Blob([...localParts, ...centralParts, end.bytes], { type: 'application/zip' });
}

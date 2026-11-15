import commonStrings from './vendor/unity-common-strings/table.mjs';

const maxTreeBytes = 1024 * 1024;
const maxNodes = 12000;
const maxDepth = 48;
const maxRows = 5000;
const maxRead = 8 * 1024 * 1024;
const alignBytes = 0x4000;
const utf8 = new TextDecoder('utf-8', { ignoreBOM: true });
// Additional common strings used by newer Unity releases.
const newerStrings = new Map([
  [1169, 'RenderingLayerMask'], [1188, 'fixed_array'], [1200, 'EntityId'],
  [1209, 'LoadableObjectId'], [1226, 'LoadableSceneId']
]);

function typeTree(bytes, version, little) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const prefix = version === 23 ? 8 : 0;
  if (bytes.length < prefix + 8) throw new Error('The embedded TypeTree header is truncated.');
  if (prefix && (view.getUint32(0, little) !== 0x7474686d || view.getUint32(4, little) !== 23)) {
    throw new Error('Unsupported embedded TypeTree revision.');
  }
  const count = view.getInt32(prefix, little);
  const stringsSize = view.getInt32(prefix + 4, little);
  const nodeSize = version >= 19 ? 32 : 24;
  const first = prefix + 8;
  const stringsStart = first + count * nodeSize;
  if (count < 1 || count > maxNodes || stringsSize < 0 || stringsStart + stringsSize > bytes.length) {
    throw new Error('The embedded TypeTree exceeds its node, string, or size limits.');
  }
  const strings = bytes.subarray(stringsStart, stringsStart + stringsSize);
  const cache = new Map();
  function getString(offset) {
    if (offset & 0x80000000) {
      const id = offset & 0x7fffffff;
      return commonStrings.get(id) ?? newerStrings.get(id) ?? '[common string ' + id + ']';
    }
    if (cache.has(offset)) return cache.get(offset);
    const end = strings.subarray(offset, offset + 513).indexOf(0);
    if (end < 0) throw new Error('Invalid local TypeTree string offset or length.');
    const result = utf8.decode(strings.subarray(offset, offset + end));
    cache.set(offset, result);
    return result;
  }
  const parents = [];
  for (let i = 0; i < count; i++) {
    const at = first + i * nodeSize;
    const level = view.getUint8(at + 2);
    if ((i === 0 ? level !== 0 : level === 0) || level > parents.length || level > maxDepth) {
      throw new Error('The embedded TypeTree has an invalid node hierarchy.');
    }
    const node = {
      type: getString(view.getUint32(at + 4, little)), name: getString(view.getUint32(at + 8, little)),
      size: view.getInt32(at + 12, little), flags: view.getUint32(at + 20, little), children: []
    };
    parents.length = level;
    if (level) parents[level - 1].children.push(node);
    parents.push(node);
  }
  return parents[0];
}

const primitives = new Map([
  ['SInt8', ['getInt8', 1]], ['UInt8', ['getUint8', 1]], ['char', ['getUint8', 1]],
  ['bool', ['getUint8', 1]], ['short', ['getInt16', 2]], ['SInt16', ['getInt16', 2]],
  ['UInt16', ['getUint16', 2]], ['unsigned short', ['getUint16', 2]],
  ['int', ['getInt32', 4]], ['SInt32', ['getInt32', 4]], ['UInt32', ['getUint32', 4]],
  ['unsigned int', ['getUint32', 4]], ['Type*', ['getUint32', 4]],
  ['long long', ['getBigInt64', 8]], ['SInt64', ['getBigInt64', 8]],
  ['unsigned long long', ['getBigUint64', 8]], ['UInt64', ['getBigUint64', 8]], ['FileSize', ['getBigUint64', 8]],
  ['float', ['getFloat32', 4]], ['double', ['getFloat64', 8]]
]);
const unsupportedTypes = new Set(['ManagedReferencesRegistry', 'ReferencedObject', 'ReferencedObjectData']);

function readValues(bytes, root, entry, info) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const little = info.littleEndian;
  const rows = [];
  let cursor = 0;
  let opaque = 0;
  let objectName;
  let textAsset;
  function reserve(size, read = false) {
    if (!Number.isSafeInteger(size) || size < 0 || size > entry.size - cursor) {
      throw new Error('A field extends past the Unity object payload.');
    }
    if (read && size > bytes.length - cursor) throw new Error('The Unity object read limit is 8 MiB.');
    const start = cursor;
    cursor += size;
    return start;
  }
  const align = () => reserve((4 - (entry.offset + cursor) % 4) % 4);
  const readCount = () => {
    const count = view.getInt32(reserve(4, true), little);
    if (count < 0) throw new Error('A Unity string or array length is negative.');
    return count;
  };

  function readData(row, length, asString) {
    const start = reserve(length);
    row.data = { offset: entry.offset + start, size: length };
    const part = bytes.subarray(start, start + Math.min(length, asString ? 480 : 24));
    row.value = asString ? utf8.decode(part) :
      Array.from(part, byte => byte.toString(16).padStart(2, '0')).join(' ');
    row.preview = part.length !== length;
  }

  function field(node, parent, depth, label = node.name, alignField = true) {
    if (depth > maxDepth || rows.length >= maxRows) throw new Error('The decoded field limit was reached.');
    if (unsupportedTypes.has(node.type)) throw new Error('Managed-reference fields require their referenced TypeTrees.');
    const start = cursor;
    const row = { id: rows.length, parent, depth, name: label, type: node.type, offset: entry.offset + start, size: null };
    rows.push(row);
    let alignAfter = alignField && Boolean(node.flags & alignBytes);
    const primitive = primitives.get(node.type);
    if (primitive) {
      const [method, width] = primitive;
      const value = view[method](reserve(width, true), little);
      row.value = node.type === 'bool' ? Boolean(value) :
        typeof value === 'bigint' || !Number.isFinite(value) ? String(value) : value;
    } else if (node.type === 'string' || node.type === 'TypelessData') {
      const length = readCount();
      readData(row, length, node.type === 'string');
      if (node.type === 'string') alignAfter = true;
    } else {
      const array = node.type === 'Array' ? node : node.children[0]?.type === 'Array' && node.children.length === 1 ? node.children[0] : null;
      if (array) {
        const [size, value] = array.children;
        if (array.children.length !== 2 || size.name !== 'size' || value.name !== 'data' ||
            !['int', 'SInt32'].includes(size.type)) throw new Error('Unsupported Unity array shape.');
        const count = readCount();
        row.itemCount = count;
        if (!value.children.length && ['char', 'UInt8', 'SInt8'].includes(value.type)) {
          readData(row, count, false);
        } else {
          for (let i = 0; i < count; i++) field(value, row.id, depth + 1, '[' + i + ']', false);
        }
        alignAfter ||= Boolean((array.flags | value.flags) & alignBytes);
      } else if (node.children.length) {
        const pointer = node.type.startsWith('PPtr<');
        let fileId;
        let pathId;
        for (const child of node.children) {
          const item = field(child, row.id, depth + 1);
          if (pointer && item.name === 'm_FileID') fileId = item.value;
          if (pointer && item.name === 'm_PathID') pathId = item.value;
        }
        if (pointer && Number.isInteger(fileId) && typeof pathId === 'string') row.reference = { fileId, pathId };
      } else if (node.type === 'Hash128' && node.size === 16) {
        const at = reserve(16, true);
        row.value = Array.from(bytes.subarray(at, at + 16), byte => byte.toString(16).padStart(2, '0')).join('');
      } else if (node.size > 0 && !node.type.startsWith('[common string ')) {
        const at = reserve(node.size);
        row.data = { offset: entry.offset + at, size: node.size };
        row.opaque = true;
        opaque++;
      } else {
        throw new Error('Unsupported TypeTree field: ' + node.type + '.');
      }
    }
    if (alignAfter) align();
    row.size = cursor - start;
    if (depth === 1 && row.name === 'm_Name' && node.type === 'string') objectName = row.value;
    if (entry.classId === 49 && depth === 1 && row.name === 'm_Script' && row.data) textAsset = row.data;
    return row;
  }

  const warnings = [];
  try {
    field(root, null, 0);
    if (cursor !== entry.size) warnings.push('The TypeTree did not account for the full object payload.');
  } catch (error) {
    warnings.push(error.message);
  }
  if (opaque) warnings.push(opaque + ' fixed-size fields were left as raw bytes.');
  return { rows, bytesAccountedFor: cursor, warnings, ...(objectName != null ? { name: objectName } : {}),
    ...(textAsset ? { textAsset } : {}) };
}

export async function inspectUnityFields(blob, report, index, progress = () => {}) {
  const entry = report.rows[index];
  const info = report.unitySerialized;
  const tree = info?.typeTrees?.[entry?.typeIndex];
  if (entry?.kind !== 'Unity object' || !entry.size || entry.offset == null || !tree) {
    throw new Error('This object has no supported embedded TypeTree or readable payload.');
  }
  if (tree.size > maxTreeBytes) throw new Error('The embedded TypeTree exceeds the 1 MiB inspection limit.');
  progress({ stage: 'Reading the embedded Unity TypeTree' });
  const schema = typeTree(new Uint8Array(await blob.slice(tree.offset, tree.offset + tree.size).arrayBuffer()), info.version, info.littleEndian);
  progress({ stage: 'Reading Unity object bytes' });
  const bytes = new Uint8Array(await blob.slice(entry.offset, entry.offset + Math.min(entry.size, maxRead)).arrayBuffer());
  progress({ stage: 'Decoding Unity object fields' });
  const result = readValues(bytes, schema, entry, info);
  const local = new Map();
  for (const [rowIndex, row] of report.rows.entries()) {
    if (row.kind === 'Unity object') local.set(row.pathId, local.has(row.pathId) ? null : rowIndex);
  }
  const externals = new Map(info.externals.map(item => [item.fileId, item.path]));
  for (const row of result.rows) {
    const ref = row.reference;
    if (!ref || ref.pathId === '0') continue;
    if (ref.fileId === 0) {
      const target = local.get(ref.pathId);
      const indexed = report.rows[target];
      if (indexed) {
        ref.target = {
          index: target, name: indexed.name, offset: indexed.offset, size: indexed.size,
          fields: indexed.offset != null && indexed.size > 0 && Boolean(info.typeTrees[indexed.typeIndex])
        };
      }
    } else if (externals.has(ref.fileId)) {
      ref.externalPath = externals.get(ref.fileId);
    }
  }
  return { schema: 'gameautopsy/unity-fields/1', pathId: entry.pathId, className: entry.className,
    objectOffset: entry.offset, objectSize: entry.size, objectIndex: index, ...result,
    status: result.warnings.length ? 'partial' : 'complete' };
}

const maxMetadata = 24 * 1024 * 1024;
const maxRows = 20000;
const unityVersion = /^(?:\d{1,4}\.){2}\d{1,4}(?:[abfpxc]\d+)?[a-z0-9._-]*(?:\n\d+)?$/i;
const decoder = new TextDecoder();
const classNames = new Map([
  [1, 'GameObject'], [4, 'Transform'], [20, 'Camera'], [21, 'Material'], [23, 'MeshRenderer'],
  [28, 'Texture2D'], [33, 'MeshFilter'], [43, 'Mesh'], [48, 'Shader'], [49, 'TextAsset'],
  [74, 'AnimationClip'], [83, 'AudioClip'], [89, 'Cubemap'], [91, 'AnimatorController'],
  [95, 'Animator'], [114, 'MonoBehaviour'], [115, 'MonoScript'], [128, 'Font'],
  [137, 'SkinnedMeshRenderer'], [142, 'AssetBundle'], [156, 'TerrainData'], [213, 'Sprite'],
  [224, 'RectTransform'], [329, 'VideoClip'], [687078895, 'SpriteAtlas']
]);
const toHex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');

function readHeader(head) {
  if (head.length < 20 || head[16] > 1) return null;
  const data = new DataView(head.buffer, head.byteOffset, head.byteLength);
  const version = data.getUint32(8);
  if (version < 17 || version > 26) return null;
  const extended = version >= 22;
  const headerSize = extended ? 48 : 20;
  if (head.length < headerSize) return null;
  const metadataSize = data.getUint32(extended ? 20 : 0);
  const fileSize = extended ? Number(data.getBigUint64(24)) : data.getUint32(4);
  const dataOffset = extended ? Number(data.getBigUint64(32)) : data.getUint32(12);
  if (!Number.isSafeInteger(fileSize) || !Number.isSafeInteger(dataOffset) ||
      metadataSize < 18 || dataOffset < headerSize + metadataSize || dataOffset > fileSize) return null;
  return { version, headerSize, metadataSize, fileSize, dataOffset, little: head[16] === 0 };
}

// The format has no magic number. Check the header and an independent version string.
export function looksLikeSerializedFile(head, name, actualSize) {
  const header = readHeader(head);
  if (!header) return false;
  const limit = Math.min(head.length, header.headerSize + 64);
  const end = head.indexOf(0, header.headerSize);
  if (end > header.headerSize && end < limit &&
      unityVersion.test(decoder.decode(head.subarray(header.headerSize, end)))) return true;
  return header.fileSize === actualSize && /(?:\.assets|\.serializedfile|\bCAB-[a-f0-9]{32})$/i.test(name);
}

function metadataReader(bytes, headerSize, little) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let position = 0;
  function take(length) {
    if (!Number.isSafeInteger(length) || length < 0 || length > bytes.length - position) {
      throw new Error('Unity metadata record exceeds the declared metadata range.');
    }
    const start = position;
    position += length;
    return start;
  }
  return {
    offset: () => headerSize + position,
    skip: take,
    align: () => take((4 - (position + headerSize) % 4) % 4),
    byte: () => view.getUint8(take(1)),
    i16: () => view.getInt16(take(2), little),
    i32: () => view.getInt32(take(4), little),
    u32: () => view.getUint32(take(4), little),
    i64: () => view.getBigInt64(take(8), little),
    string(limit = 4096) {
      const end = bytes.subarray(position, position + limit + 1).indexOf(0);
      if (end < 0) throw new Error('Unity metadata contains an unterminated or oversized string.');
      const start = take(end + 1);
      return decoder.decode(bytes.subarray(start, start + end));
    },
    hex(length) {
      const start = take(length);
      return toHex(bytes.subarray(start, start + length));
    },
    count(label, minimumSize) {
      const count = view.getInt32(take(4), little);
      if (count < 0 || count > Math.floor((bytes.length - position) / minimumSize)) {
        throw new Error('Invalid Unity ' + label + ' count.');
      }
      return count;
    }
  };
}

function readType(reader, version, typeTrees, reference) {
  const classId = reader.i32();
  const stripped = Boolean(reader.byte());
  const scriptIndex = reader.i16();
  const hasScriptId = classId === 114 || (version >= 19 && (classId === -1 || scriptIndex >= 0));
  const scriptId = hasScriptId ? reader.hex(16) : null;
  const typeHash = reader.hex(16);
  let inlineTypeTree = null;
  let typeTree;
  if (typeTrees) {
    if (version >= 23) {
      reader.skip(16);
      const size = reader.u32();
      const offset = reader.offset();
      reader.skip(size);
      inlineTypeTree = size > 0;
      if (size && version === 23) typeTree = { offset, size };
    } else {
      const offset = reader.offset();
      const nodeSize = version >= 19 ? 32 : 24;
      const nodes = reader.count('type tree node', nodeSize);
      const strings = reader.count('type tree string byte', 1);
      reader.skip(nodes * nodeSize + strings);
      inlineTypeTree = true;
      typeTree = { offset, size: reader.offset() - offset };
    }
    if (version >= 21) {
      if (reference) {
        reader.string();
        reader.string();
        reader.string();
      } else {
        reader.skip(reader.count('type dependency', 4) * 4);
      }
    }
  }
  return { classId, stripped, scriptIndex, scriptId, typeHash, inlineTypeTree, typeTree };
}

export async function inspectSerializedFile(blob, out, head, progress) {
  const { version, headerSize, metadataSize, fileSize, dataOffset, little } = readHeader(head);
  Object.assign(out.details, {
    'Serialized file version': version, 'Metadata byte order': little ? 'Little-endian' : 'Big-endian',
    'Declared file size': fileSize, 'Object data offset': dataOffset
  });
  out.rows.push({ name: 'Header', kind: 'Unity header', offset: 0, size: headerSize });
  function warning(message) {
    out.status = 'partial';
    out.warnings.push(message);
  }
  if (fileSize !== blob.size) warning('The Unity header file size differs from the selected file size.');
  if (headerSize + metadataSize > blob.size) throw new Error('The Unity metadata is truncated.');
  out.rows.push({ name: 'Metadata', kind: 'Unity metadata', offset: headerSize, size: metadataSize });
  if (metadataSize > maxMetadata) throw new Error('Unity metadata exceeds the 24 MiB inspection limit.');

  progress({ stage: 'Reading Unity metadata' });
  const reader = metadataReader(
    new Uint8Array(await blob.slice(headerSize, headerSize + metadataSize).arrayBuffer()), headerSize, little
  );
  const engineVersion = reader.string(64);
  if (engineVersion && !unityVersion.test(engineVersion)) throw new Error('Unrecognized Unity engine version string.');
  out.details['Unity engine version'] = engineVersion.split('\n', 1)[0] || 'Unspecified';
  out.details['Target platform ID'] = reader.i32();
  const flag = reader.byte();
  if (flag > 1) throw new Error('Invalid Unity type tree flag.');
  const typeTrees = flag === 1;
  out.details['Type tree metadata'] = typeTrees ? 'Enabled' : 'Disabled';
  const typeCount = reader.count('serialized type', 23);
  out.details['Serialized types'] = typeCount;
  if (typeCount > 65536) throw new Error('The Unity serialized type count exceeds the inspection limit.');
  const types = Array.from({ length: typeCount }, () => readType(reader, version, typeTrees, false));

  if (typeTrees && version >= 23) {
    out.details['Types with inline trees'] = types.filter(type => type.inlineTypeTree).length;
  }
  const objectCount = reader.count('object', version >= 22 ? 24 : 20);
  out.details['Declared objects'] = objectCount;
  const info = {
    engineVersion, version, littleEndian: little, objectCount, objectsIndexed: 0, classes: [],
    externalCount: null, externals: [], typeTrees: {}
  };
  for (const [index, type] of types.entries()) {
    if (type.typeTree) info.typeTrees[index] = type.typeTree;
  }
  out.unitySerialized = info;
  const counts = new Map();
  const pathIds = new Set();
  let duplicateIds = 0;
  let invalidTypes = 0;
  let invalidRanges = 0;
  const objectLimit = Math.min(objectCount, maxRows - out.rows.length);
  const available = Math.min(fileSize, blob.size);
  for (let index = 0; index < objectLimit; index++) {
    if (index % 512 === 0) {
      progress({ stage: 'Indexing Unity objects', done: index, total: objectLimit, unit: 'objects' });
    }
    reader.align();
    const recordOffset = reader.offset();
    const pathId = reader.i64().toString();
    const relative = version >= 22 ? Number(reader.i64()) : reader.u32();
    const size = reader.u32();
    const typeIndex = reader.i32();
    const type = types[typeIndex];
    const classId = type?.classId ?? null;
    const className = classId == null || classId === -1 ? 'Unresolved class' : classNames.get(classId) ?? 'Class ' + classId;
    const offset = dataOffset + relative;
    const validRange = Number.isSafeInteger(offset) && relative >= 0 && offset <= available && size <= available - offset;
    if (pathIds.has(pathId)) duplicateIds++;
    pathIds.add(pathId);
    if (!type) invalidTypes++;
    if (!validRange) invalidRanges++;
    const group = counts.get(classId) ?? { classId, className, count: 0 };
    group.count++;
    counts.set(classId, group);
    const note = [classId === null ? 'Invalid type index ' + typeIndex : 'Class ID ' + classId];
    if (type?.scriptIndex >= 0) note.push('Script index ' + type.scriptIndex);
    if (!validRange) note.push('Payload outside the file');
    out.rows.push({
      name: className + ' · Path ID ' + pathId, kind: 'Unity object',
      offset: validRange ? offset : null, size, pathId, classId, className, typeIndex,
      scriptIndex: type?.scriptIndex, scriptId: type?.scriptId, typeHash: type?.typeHash, stripped: type?.stripped,
      inlineTypeTree: type?.inlineTypeTree, recordOffset, recordSize: reader.offset() - recordOffset,
      open: validRange && size > 0 && size <= 128 * 1024 * 1024, note: note.join(' · ')
    });
  }
  progress({ stage: 'Indexing Unity objects', done: objectLimit, total: objectLimit, unit: 'objects' });
  info.objectsIndexed = objectLimit;
  info.classes = [...counts.values()].sort((a, b) => b.count - a.count || a.className.localeCompare(b.className));
  const topClasses = info.classes.slice(0, 10).map(item => item.className + ' (' + item.count + ')');
  if (topClasses.length) out.details['Most frequent indexed classes'] = topClasses.join(', ');
  if (duplicateIds) warning(duplicateIds + ' indexed Unity objects reuse a Path ID.');
  if (invalidTypes) warning(invalidTypes + ' indexed Unity objects have an invalid type index.');
  if (invalidRanges) warning(invalidRanges + ' indexed Unity objects point outside the declared or available file.');
  if (objectLimit < objectCount) {
    warning('The Unity object table exceeds the inspection limit. External references were not read.');
    return;
  }

  progress({ stage: 'Reading Unity external references' });
  const scriptCount = reader.count('script reference', 12);
  if (scriptCount) {
    reader.skip(4);
    reader.align();
    reader.skip(8 + (scriptCount - 1) * 12);
  }
  out.details['Script references'] = scriptCount;
  const externalCount = reader.count('external reference', 22);
  info.externalCount = externalCount;
  out.details['Declared external files'] = externalCount;
  let pathBudget = 256 * 1024;
  for (let index = 0; index < externalCount && out.rows.length < maxRows; index++) {
    const offset = reader.offset();
    reader.string();
    const guid = reader.hex(16);
    const referenceType = reader.i32();
    const path = reader.string();
    if (path.length > pathBudget) break;
    pathBudget -= path.length;
    const reference = { fileId: index + 1, path, guid, referenceType };
    out.rows.push({
      name: path || '(empty path)', kind: 'Unity external reference', offset, size: reader.offset() - offset,
      ...reference, note: 'File ID ' + reference.fileId + ' · GUID ' + guid
    });
    info.externals.push(reference);
  }
  if (info.externals.length < externalCount) {
    warning('The Unity external reference list reached the inspection limit.');
    return;
  }
  if (version >= 20) {
    const referenceTypes = reader.count('reference type', 23);
    out.details['Managed reference types'] = referenceTypes;
    if (referenceTypes > 65536) throw new Error('The Unity reference type list exceeds the inspection limit.');
    for (let index = 0; index < referenceTypes; index++) readType(reader, version, typeTrees, true);
  }
  if (version >= 26) {
    const subtreeCount = reader.count('shared subtree', 20);
    out.details['Shared type subtrees'] = subtreeCount;
    if (subtreeCount > 65536) throw new Error('The Unity shared subtree list exceeds the inspection limit.');
    for (let index = 0; index < subtreeCount; index++) {
      reader.skip(16);
      reader.skip(reader.u32());
    }
  }
}

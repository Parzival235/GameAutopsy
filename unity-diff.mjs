import { compareBytes } from './binary-diff.mjs?v=0.13.0';
import { inspectUnityFields } from './unity-fields.mjs?v=0.13.0';

const MiB = 1024 * 1024;
const limits = { pairs: 768, bytes: 128 * MiB, objectBytes: 8 * MiB, rows: 5000, fieldsPerObject: 40, fieldsTotal: 1200, fieldReportChars: 2 * MiB };

function groupObjects(report) {
  const objects = new Map();
  for (const [index, row] of report.rows.entries()) {
    if (row.kind !== 'Unity object') continue;
    const group = objects.get(row.pathId) ?? [];
    group.push({ index, ...row });
    objects.set(row.pathId, group);
  }
  return objects;
}

function fieldsByPath(rows, identity) {
  const known = new Map();
  const paths = [];
  const seen = new Map();
  for (const row of rows) {
    const parent = paths[row.parent];
    if (row.parent !== null && !parent) continue;
    if (row.parent !== null && rows[row.parent].reference && ['m_FileID', 'm_PathID'].includes(row.name)) continue;
    const path = row.parent === null ? [] : [...(parent?.path ?? []), row.name];
    const base = JSON.stringify([parent?.key ?? 0, row.parent === null ? '' : row.name]);
    const occurrence = seen.get(base) ?? 0;
    seen.set(base, occurrence + 1);
    const token = base + ':' + occurrence;
    if (!identity.has(token)) identity.set(token, identity.size + 1);
    const key = identity.get(token);
    paths[row.id] = { key, path };
    known.set(key, { ...row, path, occurrence });
  }
  return known;
}

function pointer(ref, external) {
  if (ref.pathId === '0') return { key: 'null', value: ref };
  if (ref.fileId === 0) return { key: 'local:' + ref.pathId, value: ref };
  const entry = external.get(ref.fileId);
  if (!entry || (!entry.path && !/[^0]/.test(entry.guid))) return { key: null, value: ref };
  return {
    key: JSON.stringify([entry.path, entry.guid, entry.referenceType, ref.pathId]),
    value: { fileId: ref.fileId, pathId: ref.pathId, path: entry.path, guid: entry.guid }
  };
}

function evidence(row, resolved) {
  if (!row) return null;
  return { type: row.type, offset: row.offset, size: row.size,
    ...(row.value != null ? { value: Object.is(row.value, -0) ? '-0' : row.value } : {}),
    ...(row.itemCount != null ? { itemCount: row.itemCount } : {}),
    ...(row.data ? { data: row.data, preview: row.preview ?? false } : {}),
    ...(resolved ? { reference: resolved.value } : {}) };
}

function describe(row) {
  return row ? { classId: row.classId, className: row.className, typeHash: row.typeHash, offset: row.offset, size: row.size } : null;
}

async function compareFields(before, after, left, right, context, claim, saveField, progress) {
  if (!claim(left.size + right.size)) return { available: false, reason: 'fieldByteBudget' };
  let a, b;
  try {
    a = await inspectUnityFields(before.blob, before.report, left.index, progress, { resolveTargets: false });
    b = await inspectUnityFields(after.blob, after.report, right.index, progress, { resolveTargets: false });
  } catch (error) {
    return { available: false, reason: 'fieldDecodeFailed', error: error.message };
  }
  const fields = [];
  let changes = 0;
  let unknownFields = 0;
  let comparedFields = 0;
  const identity = new Map();
  const am = fieldsByPath(a.rows, identity);
  const bm = fieldsByPath(b.rows, identity);
  for (const key of new Set([...am.keys(), ...bm.keys()])) {
    const old = am.get(key);
    const next = bm.get(key);
    let kind;
    let ar, br;
    let firstDataDifference;
    if (!old || !next) {
      if ((old ?? next).size != null && (!old ? a : b).status === 'complete') kind = old ? 'removed' : 'added';
      else unknownFields++;
    } else if (old.size == null || next.size == null) {
      unknownFields++;
    } else if (old.type !== next.type || old.itemCount !== next.itemCount) {
      kind = 'layoutChanged';
    } else if (old.reference || next.reference) {
      if (old.reference && next.reference) {
        ar = pointer(old.reference, context.beforeExternal);
        br = pointer(next.reference, context.afterExternal);
        if (ar.key == null || br.key == null) unknownFields++;
        else if (ar.key !== br.key) kind = 'referenceChanged';
        else comparedFields++;
      } else unknownFields++;
    } else if (old.data && next.data) {
      if (old.data.size !== next.data.size) kind = 'dataChanged';
      else if (claim(old.data.size + next.data.size)) {
        const x = before.blob.slice(old.data.offset, old.data.offset + old.data.size);
        const y = after.blob.slice(next.data.offset, next.data.offset + next.data.size);
        const diff = await compareBytes(x, y);
        if (diff.totalRanges) {
          kind = 'dataChanged';
          firstDataDifference = diff.ranges[0].offset;
        } else comparedFields++;
      } else unknownFields++;
    } else if (old.data || next.data) {
      unknownFields++;
    } else if (!Object.is(old.value, next.value)) {
      kind = 'valueChanged';
    } else if (old.value != null) {
      comparedFields++;
    }
    if (kind) {
      changes++;
      if (fields.length < limits.fieldsPerObject) {
        const field = { path: (old ?? next).path, occurrence: (old ?? next).occurrence, kind,
          before: evidence(old, ar ?? (old?.reference ? pointer(old.reference, context.beforeExternal) : null)),
          after: evidence(next, br ?? (next?.reference ? pointer(next.reference, context.afterExternal) : null)),
          ...(firstDataDifference != null ? { firstDataDifference } : {}) };
        if (saveField(field)) fields.push(field);
      }
    }
  }
  return { available: true, complete: a.status === 'complete' && b.status === 'complete' && !unknownFields,
    beforeStatus: a.status, afterStatus: b.status, warnings: { before: a.warnings, after: b.warnings },
    changes, unknownFields, comparedFields, omitted: changes - fields.length, fields };
}

const externalMap = info => new Map(info.externals.map(row => [row.fileId, row]));

export async function compareUnityFiles(before, after, pathId = '', progress = () => {}) {
  const a = before.report.unitySerialized;
  const b = after.report.unitySerialized;
  if (!a || !b) throw new Error('Choose two Unity serialized files.');
  if (pathId && !/^-?\d{1,19}$/.test(pathId)) throw new Error('Enter a decimal Unity Path ID.');
  const selected = pathId ? BigInt(pathId) : null;
  if (selected != null && (selected < -(1n << 63n) || selected >= (1n << 63n))) {
    throw new Error('Path ID must fit a signed 64-bit integer.');
  }
  const old = groupObjects(before.report);
  const next = groupObjects(after.report);
  const ids = selected == null ? new Set([...old.keys(), ...next.keys()]) : new Set([String(selected)]);
  const completeA = a.objectsIndexed === a.objectCount;
  const completeB = b.objectsIndexed === b.objectCount;
  const context = { beforeExternal: externalMap(a), afterExternal: externalMap(b) };
  const mappingsMatch = a.externalCount === a.externals.length && b.externalCount === b.externals.length &&
    JSON.stringify(a.externals) === JSON.stringify(b.externals);
  const counts = { added: 0, removed: 0, classChanged: 0, fieldsChanged: 0, fieldsEqual: 0, bytesChanged: 0,
    metadataChanged: 0, moved: 0, byteEqual: 0, unknown: 0 };
  const skipped = {};
  const rows = [];
  let processed = 0, omittedRows = 0, bytesBudgeted = 0, pairs = 0, fieldRows = 0, fieldReportChars = 0;
  let fieldPairs = 0, partialFieldPairs = 0, omittedFields = 0;
  const claim = size => {
    if (size > limits.bytes - bytesBudgeted) return false;
    bytesBudgeted += size;
    return true;
  };
  const saveField = field => {
    const length = JSON.stringify(field).length;
    if (fieldRows >= limits.fieldsTotal || length > limits.fieldReportChars - fieldReportChars) return false;
    fieldRows++;
    fieldReportChars += length;
    return true;
  };
  function save(id, status, left, right, detail = {}) {
    counts[status]++;
    if (detail.reason) skipped[detail.reason] = (skipped[detail.reason] ?? 0) + 1;
    if (status === 'byteEqual' && selected == null) return;
    if (rows.length >= limits.rows) {
      omittedRows++;
      return;
    }
    rows.push({ pathId: id, status, before: describe(left), after: describe(right), ...detail });
  }
  for (const id of ids) {
    if (processed % 32 === 0) progress({ stage: 'Comparing Unity objects', done: processed, total: ids.size, unit: 'Path IDs' });
    processed++;
    const [left, ...othersA] = old.get(id) ?? [];
    const [right, ...othersB] = next.get(id) ?? [];
    if (othersA.length || othersB.length) {
      save(id, 'unknown', left, right, { reason: 'duplicatePathId' });
    } else if (!left || !right) {
      const known = left ? completeB : completeA;
      if (known && (left || right)) save(id, left ? 'removed' : 'added', left, right);
      else save(id, 'unknown', left, right, { reason: left || right ? 'incompleteObjectTable' : 'pathNotIndexed' });
    } else if (left.classId == null || right.classId == null || left.classId < 0 || right.classId < 0) {
      save(id, 'unknown', left, right, { reason: 'unknownClass' });
    } else if (left.classId !== right.classId) {
      save(id, 'classChanged', left, right);
    } else if (left.offset == null || right.offset == null) {
      save(id, 'unknown', left, right, { reason: 'invalidPayloadRange' });
    } else if (Math.max(left.size, right.size) > limits.objectBytes) {
      save(id, 'unknown', left, right, { reason: 'objectSizeLimit' });
    } else if (pairs >= limits.pairs || !claim(left.size + right.size)) {
      save(id, 'unknown', left, right, { reason: 'comparisonBudget' });
    } else {
      pairs++;
      const x = before.blob.slice(left.offset, left.offset + left.size);
      const y = after.blob.slice(right.offset, right.offset + right.size);
      const raw = await compareBytes(x, y);
      const bytes = { equal: raw.totalRanges === 0, firstDifference: raw.ranges[0]?.offset ?? null,
        changed: raw.changed, beforeOnly: raw.beforeOnly, afterOnly: raw.afterOnly };
      const sameType = left.typeHash === right.typeHash && a.littleEndian === b.littleEndian;
      const moved = left.offset !== right.offset;
      if (bytes.equal && sameType && mappingsMatch) {
        save(id, moved ? 'moved' : 'byteEqual', left, right, { bytes });
        continue;
      }
      const supported = a.typeTrees[left.typeIndex] && b.typeTrees[right.typeIndex] && left.size && right.size;
      const fieldDiff = supported ? await compareFields(before, after, left, right, context, claim, saveField, () => {}) :
        { available: false, reason: 'missingEmbeddedTypeTree' };
      if (fieldDiff.available) {
        fieldPairs++;
        if (!fieldDiff.complete) partialFieldPairs++;
        omittedFields += fieldDiff.omitted;
      }
      const status = fieldDiff.changes ? 'fieldsChanged' :
        fieldDiff.complete ? (sameType ? 'fieldsEqual' : 'metadataChanged') :
        !bytes.equal ? 'bytesChanged' : !sameType ? 'metadataChanged' : 'unknown';
      save(id, status, left, right, { bytes, moved, metadataChanged: !sameType, fieldDiff,
        ...(!fieldDiff.available ? { reason: fieldDiff.reason } : {}) });
    }
  }
  progress({ stage: 'Comparing Unity objects', done: processed, total: ids.size, unit: 'Path IDs' });
  return {
    schema: 'gameautopsy/unity-diff/1',
    baseline: before.report.name, candidate: after.report.name,
    baselinePath: before.path ?? [before.report.name],
    candidatePath: after.report.source?.container ? [after.report.source.container, after.report.name] : [after.report.name],
    ...(after.report.source?.container ? { candidateContainer: after.report.source.container } : {}),
    ...(selected != null ? { pathId: String(selected) } : {}), counts, rows,
    coverage: { matchedBy: 'pathId', limits, beforeIndexed: a.objectsIndexed, beforeDeclared: a.objectCount,
      afterIndexed: b.objectsIndexed, afterDeclared: b.objectCount, pathsConsidered: processed, pairs, bytesBudgeted,
      fieldPairs, partialFieldPairs, fieldRows, omittedFields, omittedRows, skipped }
  };
}

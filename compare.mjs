export function entriesByName(report) {
  const entries = new Map();
  for (const row of report.rows) {
    if (row.kind === 'Directory') continue;
    const group = entries.get(row.name);
    if (group) group.push(row);
    else entries.set(row.name, [row]);
  }
  return entries;
}

function fingerprint(entry) {
  return {
    size: entry.size, packed: entry.packed, crc32: entry.crc32, method: entry.method,
    flags: entry.flags, offset: entry.offset
  };
}

export const isCompleteZip = report => report.format === 'ZIP' &&
  report.status === 'ok' && report.rows.length === report.details['Declared entries'];

export function compareArchives(baseline, candidate, verification) {
  if (![baseline, candidate].every(isCompleteZip)) {
    throw new Error('Comparison requires two complete ZIP directories. Check archive warnings and limits.');
  }
  const before = entriesByName(baseline);
  const after = entriesByName(candidate);
  const names = [...new Set([...before.keys(), ...after.keys()])].sort();
  const counts = { added: 0, removed: 0, changed: 0, repacked: 0, moved: 0, matched: 0, ambiguous: 0, encrypted: 0 };
  const rows = [];
  for (const name of names) {
    const left = before.get(name) ?? [];
    const right = after.get(name) ?? [];
    const a = left[0];
    const b = right[0];
    let status;
    if (left.length > 1 || right.length > 1) status = 'ambiguous';
    else if (!a) status = 'added';
    else if (!b) status = 'removed';
    else if ((a.flags | b.flags) & 0x2041) status = 'encrypted';
    else if (a.size !== b.size || a.crc32 !== b.crc32) status = 'changed';
    else if (a.packed !== b.packed || a.method !== b.method || a.flags !== b.flags) status = 'repacked';
    else if (a.offset !== b.offset) status = 'moved';
    else status = 'matched';
    const payload = verification?.evidence.get(name);
    const metadataStatus = status;
    if (payload?.status === 'different') status = 'payloadChanged';
    counts[status] = (counts[status] ?? 0) + 1;
    if (status === 'matched' && !payload) continue;
    rows.push({
      name, status, before: left.map(fingerprint), after: right.map(fingerprint),
      ...(payload ? { metadataStatus, payload } : {}),
      canDiff: left.length === 1 && right.length === 1 && Boolean(a?.open && b?.open),
      packedDelta: status === 'ambiguous' ? null : (b?.packed ?? 0) - (a?.packed ?? 0)
    });
  }
  return { schema: 'gameautopsy/zip-comparison/1', baseline: baseline.name, candidate: candidate.name, counts, rows,
    ...(verification ? { payloadCoverage: verification.coverage } : {}) };
}

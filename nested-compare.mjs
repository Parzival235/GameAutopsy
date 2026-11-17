import { analyze, MiB, openZipMember } from './formats.mjs?v=0.12.1';
import { compareArchives, entriesByName } from './compare.mjs?v=0.12.1';
import { archivePriority, nestedZipName } from './zip-content-diff.mjs?v=0.12.1';

const maxDepth = 3;
const maxPairs = 24;
const maxRows = 20000;
const maxBytes = 256 * MiB;
export async function compareNestedArchives(before, after, result, progress = () => {}, verify) {
  const coverage = { groups: [], notices: [], skipped: 0, matchingArchives: 0, byteEqualArchives: 0, attempted: 0, bytesBudgeted: 0 };
  let rows = 0;

  function skip(path, reason) {
    coverage.skipped++;
    if (coverage.notices.length < 60) coverage.notices.push({ path, reason });
  }

  async function walk(left, right, parent, path) {
    const a = entriesByName(left.report);
    const b = entriesByName(right.report);
    const names = [...new Set([...a.keys(), ...b.keys()])].filter(name => nestedZipName.test(name));
    names.sort((x, y) => archivePriority(x) - archivePriority(y));
    const compared = new Map(parent.rows.map(row => [row.name, row]));
    for (const name of names) {
      const location = [...path, name];
      const old = a.get(name);
      const next = b.get(name);
      if (!old || !next) {
        skip(location, 'Archive path is present on only one side.');
        continue;
      }
      if (old.length !== 1 || next.length !== 1) {
        skip(location, 'Duplicate archive path.');
        continue;
      }
      const [first] = old;
      const [second] = next;
      if (!first.open || !second.open) {
        skip(location, 'Archive entry uses unsupported compression or encryption.');
        continue;
      }
      const row = compared.get(name);
      if (row?.payload?.status === 'equal') {
        coverage.byteEqualArchives++;
        continue;
      }
      const status = row?.status ?? 'matched';
      if (status === 'matched' || status === 'moved') {
        coverage.matchingArchives++;
        continue;
      }
      const cost = first.size + first.packed + second.size + second.packed;
      if (path.length >= maxDepth || coverage.attempted >= maxPairs || rows >= maxRows ||
          cost > maxBytes - coverage.bytesBudgeted ||
          Math.max(first.size, first.packed, second.size, second.packed) > 128 * MiB) {
        skip(location, 'Archive pair exceeds a depth, entry size, byte or result limit.');
        continue;
      }
      coverage.attempted++;
      coverage.bytesBudgeted += cost;
      progress({ stage: 'Comparing nested archives', detail: coverage.attempted + ' archive pairs visited' });
      try {
        const firstBlob = (await openZipMember(left.blob, first)).blob;
        const secondBlob = (await openZipMember(right.blob, second)).blob;
        const oldReport = await analyze(firstBlob, name);
        const newReport = await analyze(secondBlob, name);
        const before = { blob: firstBlob, report: oldReport };
        const after = { blob: secondBlob, report: newReport };
        const comparison = compareArchives(oldReport, newReport);
        if (verify && comparison.rows.length <= maxRows - rows) {
          const checked = await verify(before, after, progress);
          Object.assign(comparison, compareArchives(oldReport, newReport, checked));
        }
        if (comparison.rows.length > maxRows - rows) {
          skip(location, 'The nested comparison would exceed the total result-row limit.');
          continue;
        }
        rows += comparison.rows.length;
        coverage.groups.push({ path: location, counts: comparison.counts, rows: comparison.rows,
          ...(comparison.payloadCoverage ? { payloadCoverage: comparison.payloadCoverage } : {}) });
        await walk(before, after, comparison, location);
      } catch (error) {
        skip(location, error.message);
      }
    }
  }

  await walk(before, after, result, []);
  return coverage;
}

import { analyze, MiB, openZipMember } from './formats.mjs?v=0.7.0';
import { compareArchives, entriesByName } from './compare.mjs';

const maxDepth = 3;
const maxPairs = 24;
const maxRows = 20000;
const maxBytes = 256 * MiB;
const archiveName = /\.(?:zip|apk|apks|xapk|aab|ipa|obb)$/i;
const priority = name => /(?:^|\/)(?:base|universal)\.apk$/i.test(name) ? 0 : /\.apk$/i.test(name) ? 1 : 2;

export async function compareNestedArchives(before, after, result, progress = () => {}) {
  const coverage = { groups: [], notices: [], skipped: 0, matchingArchives: 0, attempted: 0, bytesBudgeted: 0 };
  let rows = 0;

  function skip(path, reason) {
    coverage.skipped++;
    if (coverage.notices.length < 60) coverage.notices.push({ path, reason });
  }

  async function walk(left, right, parent, path) {
    const a = entriesByName(left.report);
    const b = entriesByName(right.report);
    const names = [...new Set([...a.keys(), ...b.keys()])].filter(name => archiveName.test(name));
    names.sort((x, y) => priority(x) - priority(y));
    const statuses = new Map(parent.rows.map(row => [row.name, row.status]));
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
      const status = statuses.get(name) ?? 'matched';
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
        const comparison = compareArchives(oldReport, newReport);
        if (comparison.rows.length > maxRows - rows) {
          skip(location, 'The nested comparison would exceed the total result-row limit.');
          continue;
        }
        rows += comparison.rows.length;
        coverage.groups.push({ path: location, counts: comparison.counts, rows: comparison.rows });
        await walk({ blob: firstBlob, report: oldReport }, { blob: secondBlob, report: newReport }, comparison, location);
      } catch (error) {
        skip(location, error.message);
      }
    }
  }

  await walk(before, after, result, []);
  return coverage;
}

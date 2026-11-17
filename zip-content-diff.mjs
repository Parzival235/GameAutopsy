import { compareBytes } from './binary-diff.mjs?v=0.12.1';
import { entriesByName } from './compare.mjs?v=0.12.1';
import { MiB, openZipMember } from './formats.mjs?v=0.12.1';

const maxPairs = 512;
const maxPairsPerArchive = 256;
const maxBytes = 192 * MiB;
const maxEntry = 32 * MiB;
export const nestedZipName = /\.(?:zip|apk|apks|apkm|xapk|aab|ipa|obb)$/i;
export const archivePriority = name => /(?:^|\/)(?:base|universal)\.apk$/i.test(name) ? 0 : /\.apk$/i.test(name) ? 1 : 2;

export function createPayloadComparison() {
  let attempted = 0;
  let budgetedBytes = 0;
  return async function verify(before, after, progress = () => {}) {
    const left = entriesByName(before.report);
    const right = entriesByName(after.report);
    const shared = [...left.keys()].filter(name => right.has(name));
    // Check archive members first, including metadata matches that may hide a nested change.
    shared.sort((a, b) => Number(nestedZipName.test(b)) - Number(nestedZipName.test(a)) ||
      archivePriority(a) - archivePriority(b));
    const counts = { shared: shared.length, attempted: 0, equal: 0, different: 0, failed: 0,
      ambiguous: 0, unavailable: 0, sizeLimit: 0, budgetLimit: 0 };
    const evidence = new Map();
    const limits = { maxPairs, maxPairsPerArchive, maxBytes, maxEntry };
    for (const name of shared) {
      const old = left.get(name);
      const next = right.get(name);
      if (old.length !== 1 || next.length !== 1) {
        counts.ambiguous++;
        continue;
      }
      const [a] = old;
      const [b] = next;
      if (!a.open || !b.open) {
        counts.unavailable++;
        continue;
      }
      if (Math.max(a.packed, b.packed, a.size, b.size) > maxEntry) {
        counts.sizeLimit++;
        continue;
      }
      const cost = a.packed + a.size + b.packed + b.size;
      if (attempted >= maxPairs || counts.attempted >= maxPairsPerArchive || cost > maxBytes - budgetedBytes) {
        counts.budgetLimit++;
        continue;
      }
      attempted++;
      counts.attempted++;
      budgetedBytes += cost;
      progress({ stage: 'Verifying ZIP entry bytes', detail: name + ' · ' + attempted + ' pairs attempted' });
      let verdict;
      try {
        const verifiedA = await openZipMember(before.blob, a);
        const verifiedB = await openZipMember(after.blob, b);
        const diff = await compareBytes(verifiedA.blob, verifiedB.blob);
        if (diff.totalRanges) {
          verdict = {
            status: 'different', firstDifference: diff.ranges[0].offset, differingBytes: diff.changed,
            beforeOnly: diff.beforeOnly, afterOnly: diff.afterOnly,
            sameSizeAndCrc32: a.size === b.size && a.crc32 === b.crc32
          };
        } else {
          verdict = { status: 'equal' };
        }
      } catch (error) {
        verdict = { status: 'failed', reason: error.message };
      }
      counts[verdict.status]++;
      evidence.set(name, verdict);
    }
    return { coverage: { counts, limits, budgetedBytesTotal: budgetedBytes }, evidence };
  };
}

import { archiveFormat, inventoryReader } from './archive-members.mjs?v=0.14.0';
import { filterInventory } from './inventory-scope.mjs?v=0.14.0';
import { parsePattern, scanPattern } from './byte-search.mjs?v=0.14.0';

const MiB = 1024 * 1024;
const limits = Object.freeze({
  entries: 100, offsets: 16 * MiB, matches: 150, probes: 8_000_000, workBytes: 192 * MiB, memberBytes: 32 * MiB
});

export function planInventorySearch(inventory, query, mode, pathFilter = '', category = '') {
  if (!inventory) throw new Error('Index the root archive before searching its contents.');
  if (typeof query !== 'string' || query.length > 384 || typeof pathFilter !== 'string' ||
      pathFilter.length > 512 || typeof category !== 'string' || category.length > 32) {
    throw new Error('The inventory search query or filter is too long.');
  }
  const pattern = parsePattern(query, mode);
  const matching = filterInventory(inventory.rows, pathFilter, category);
  const members = matching.filter(row => !archiveFormat(row.detectedFormat));
  return { inventory, pattern, members, query, mode, pathFilter, category, containers: matching.length - members.length };
}

function locate(row) {
  const path = [...row.path, row.name];
  return {
    id: row.id, route: row.route, path: path.map(name => name.slice(0, 1024)),
    ...(path.some(name => name.length > 1024) ? { pathShortened: true } : {})
  };
}

export async function searchInventory(root, plan, start = { member: 0, offset: 0 }, progress = () => {}) {
  const { inventory, pattern, members, query, mode, pathFilter, category, containers } = plan;
  const result = {
    schema: 'gameautopsy/inventory-search/1', root: root.report.name, query, mode, pathFilter, category,
    length: pattern.length, members: members.length, containers, start, next: null, limits,
    inventoryCoverage: { skipped: inventory.skipped, truncated: inventory.truncated },
    visited: 0, completed: 0, offsetsChecked: 0, probes: 0, workBytes: 0, matches: 0, hits: [], skipped: []
  };
  const budgetError = new Error('Opening the entry would exceed the batch read budget.');
  const read = inventoryReader(root, size => {
    if (!Number.isSafeInteger(size) || size < 0 || size > limits.workBytes - result.workBytes) throw budgetError;
    result.workBytes += size;
  });
  let { member, offset } = start;
  const update = detail => progress({ stage: 'Searching archive contents', done: member, total: members.length, unit: 'entries', detail });
  while (member < members.length && result.visited < limits.entries && result.matches < limits.matches &&
      result.offsetsChecked < limits.offsets && result.probes < limits.probes) {
    const row = members[member];
    const workBefore = result.workBytes;
    update(row.name.slice(0, 160));
    try {
      if (!row.open) throw new Error('The entry is available as metadata only.');
      if (Math.max(row.size, row.packed ?? 0) > limits.memberBytes) throw new Error('The entry exceeds the 32 MiB member limit.');
      const { blob, source, format } = await read(row);
      const scan = await scanPattern(blob, pattern, offset, {
        maxOffsets: limits.offsets - result.offsetsChecked,
        maxHits: limits.matches - result.matches,
        maxProbes: limits.probes - result.probes
      });
      result.visited++;
      result.matches += scan.offsets.length;
      result.offsetsChecked += scan.end - scan.from;
      result.probes += scan.probes;
      if (scan.offsets.length) result.hits.push({ ...locate(row), size: blob.size, containerFormat: format, source, offsets: scan.offsets });
      if (scan.next != null) {
        offset = scan.next;
        break;
      }
      result.completed++;
    } catch (error) {
      if (error === budgetError && workBefore > 0) break; // Retry this entry with a fresh budget.
      result.visited++;
      result.skipped.push({ ...locate(row), reason: error.message.slice(0, 240) });
    }
    member++;
    offset = 0;
  }
  update('Search pass complete');
  if (member < members.length) result.next = { member, offset };
  return result;
}

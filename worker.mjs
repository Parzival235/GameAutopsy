import { preview, sampleStrings } from './formats.mjs?v=0.5.0';
import { compareArchives } from './compare.mjs?v=0.5.0';
import { compareNestedArchives } from './nested-compare.mjs?v=0.5.0';
import { checkZip, verifyZipPayloads } from './zip-checks.mjs?v=0.5.0';
import { searchBytes } from './byte-search.mjs';

import { archiveFormat, inspect, maxDepth, maxExpanded, openMember } from './archive-members.mjs';
import { buildInventory } from './inventory.mjs';
import { compareBytes, previewDiff } from './binary-diff.mjs';

const stack = [];
let inventory;
let bytePair;

async function appendMember(nodes, index) {
  if (nodes.length >= maxDepth + 1) throw new Error('The six-level nesting limit has been reached.');
  const parent = nodes.at(-1);
  const entry = parent.report.rows[index];
  if (!entry?.open) throw new Error('That entry cannot be opened.');
  const retained = nodes.slice(1).reduce((sum, node) => sum + node.blob.size, 0);
  if (retained + entry.size > maxExpanded) throw new Error('Open entries would exceed the combined 256 MiB limit.');
  nodes.push(await openMember(parent, entry));
}

function current() {
  if (!stack.length) throw new Error('Choose a file first.');
  return stack.at(-1);
}

function listing() {
  return {
    path: stack.map(node => node.report.name),
    report: current().report, inventoryAvailable: archiveFormat(stack[0].report.format)
  };
}

async function run({ action, file, index, offset, query, mode, nested }, progress) {
  switch (action) {
    case 'open':
      stack.splice(0, stack.length, await inspect(file, file.name));
      inventory = undefined;
      bytePair = undefined;
      return listing();
    case 'member':
      await appendMember(stack, index);
      bytePair = undefined;
      return listing();
    case 'parent':
      if (stack.length > 1) {
        stack.pop();
        bytePair = undefined;
      }
      return listing();
    case 'inventory':
      if (!stack.length) throw new Error('Choose a file first.');
      inventory = await buildInventory(stack[0], progress);
      return inventory;
    case 'inventory-open': {
      const record = inventory?.rows[index];
      if (!record?.open) throw new Error('That inventory entry cannot be opened.');
      const next = [stack[0]];
      for (const entryIndex of record.route) await appendMember(next, entryIndex);
      stack.splice(0, stack.length, ...next);
      bytePair = undefined;
      return listing();
    }
    case 'diff-bytes': {
      const left = current();
      const candidate = file ?? bytePair?.after;
      if (!candidate) throw new Error('Choose a candidate file first.');
      const result = await compareBytes(left.blob, candidate, offset, progress);
      bytePair = { before: left.blob, after: candidate };
      return { ...result, schema: 'gameautopsy/byte-diff/1', before: left.report.name, after: candidate.name, path: listing().path };
    }
    case 'diff-preview':
      if (!bytePair) throw new Error('Compare two files first.');
      return previewDiff(bytePair.before, bytePair.after, offset);
    case 'compare': {
      const before = current();
      const after = await inspect(file, file.name);
      const result = compareArchives(before.report, after.report);
      if (nested) result.nested = await compareNestedArchives(before, after, result);
      return result;
    }
    case 'checks': {
      const { blob, report } = current();
      const layout = await checkZip(blob, report);
      report.zipChecks = { ...layout, ...(report.zipChecks?.integrity ? { integrity: report.zipChecks.integrity } : {}) };
      return report.zipChecks;
    }
    case 'verify-zip': {
      const { blob, report } = current();
      const layout = report.zipChecks ?? await checkZip(blob, report);
      report.zipChecks = { ...layout, integrity: await verifyZipPayloads(blob, report) };
      return report.zipChecks;
    }
    case 'download': {
      if (stack.length <= 1) throw new Error('Open an archive member first.');
      return current().blob;
    }
    case 'search-bytes': return searchBytes(current().blob, query, mode, offset);
    case 'hex': return preview(current().blob, offset);
    case 'strings': return sampleStrings(current().blob);
    case 'sha256': {
      const { blob } = current();
      if (blob.size > maxExpanded) throw new Error('Whole-file SHA-256 is available for files up to 256 MiB.');
      const digest = await crypto.subtle.digest('SHA-256', await blob.arrayBuffer());
      return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
    }
    default: throw new Error('Unknown action.');
  }
}

self.addEventListener('message', async event => {
  const { id } = event.data;
  try {
    self.postMessage({ id, data: await run(event.data, progress => self.postMessage({ id, progress })) });
  } catch (error) {
    self.postMessage({ id, error: error.message });
  }
});

import { preview, sampleStrings, MiB } from './formats.mjs?v=0.6.0';
import { compareArchives } from './compare.mjs?v=0.6.0';
import { compareNestedArchives } from './nested-compare.mjs?v=0.6.0';
import { checkZip, verifyZipPayloads } from './zip-checks.mjs?v=0.6.0';
import { searchBytes } from './byte-search.mjs?v=0.6.0';
import { archiveFormat, inspect, maxDepth, maxExpanded, openMember } from './archive-members.mjs?v=0.6.0';
import { buildInventory } from './inventory.mjs?v=0.6.0';
import { compareBytes, previewDiff } from './binary-diff.mjs?v=0.6.0';
import { interpretBytes } from './hex.mjs';
import { createReportSession } from './report-session.mjs';

const stack = [];
let inventory;
let bytePair;
let session = createReportSession();

async function appendMember(nodes, index, progress) {
  if (nodes.length >= maxDepth + 1) throw new Error('The six-level nesting limit has been reached.');
  const parent = nodes.at(-1);
  const entry = parent.report.rows[index];
  if (!entry?.open) throw new Error('That entry cannot be opened.');
  const retained = nodes.slice(1).reduce((sum, node) => sum + node.blob.size, 0);
  if (retained + entry.size > maxExpanded) throw new Error('Open entries would exceed the combined 256 MiB limit.');
  const node = await openMember(parent, entry, progress);
  node.route = [...parent.route, index];
  node.path = [...parent.path, node.report.name];
  nodes.push(node);
}

function current() {
  if (!stack.length) throw new Error('Choose a file first.');
  return stack.at(-1);
}

function listing() {
  const { path, report } = current();
  return { path, report, inventoryAvailable: archiveFormat(stack[0].report.format) };
}

async function zipChecks(node, progress, verify = false, refresh = false) {
  const { blob, report } = node;
  const existing = report.zipChecks;
  const layout = (!refresh && existing) || await checkZip(blob, report, progress);
  report.zipChecks = existing?.integrity ? { ...layout, integrity: existing.integrity } : layout;
  if (verify) {
    const integrity = await verifyZipPayloads(blob, report, progress);
    report.zipChecks = { ...report.zipChecks, integrity };
  }
  return report.zipChecks;
}

async function sha256(blob, progress) {
  if (blob.size > maxExpanded) throw new Error('Whole-file SHA-256 is available for files up to 256 MiB.');
  const buffer = new Uint8Array(blob.size);
  let done = 0;
  let last = 0;
  const update = () => progress({ stage: 'Reading bytes for SHA-256', done, total: blob.size, unit: 'bytes' });
  update();
  const reader = blob.stream().getReader();
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      buffer.set(chunk.value, done);
      done += chunk.value.length;
      if (done >= last + 4 * MiB) {
        update();
        last = done;
      }
    }
  } finally {
    reader.releaseLock();
  }
  if (done !== blob.size) throw new Error('The file ended before all SHA-256 bytes were read.');
  update();
  progress({ stage: 'Computing SHA-256 digest' });
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

async function startHex(blob, offset) {
  const data = await preview(blob, offset);
  const typed = little => Object.fromEntries(Object.entries(interpretBytes(data.bytes, little)).map(([key, value]) =>
    [key, typeof value === 'bigint' || (typeof value === 'number' && !Number.isFinite(value)) ? String(value) : value]
  ));
  return { ...data, littleEndian: typed(true), bigEndian: typed(false) };
}

async function fullReport(progress) {
  const node = current();
  const { blob, report } = node;
  const root = stack[0];
  const automatic = [];
  const existingInventory = inventory;
  async function job(kind, label, target, status, work) {
    if (status) {
      automatic.push({ kind, path: target.path, route: target.route, status });
      return;
    }
    try {
      progress({ stage: label, detail: target.report.name });
      await work();
      automatic.push({ kind, path: target.path, route: target.route, status: 'complete' });
    } catch (error) {
      automatic.push({ kind, path: target.path, route: target.route, status: 'error', message: error.message });
    }
  }
  await job('hexPreview', 'Reading initial hex preview', node, report.initialHex ? 'reused' : null,
    async () => { report.initialHex = await startHex(blob, 0); });
  await job('strings', 'Sampling strings', node, report.strings ? 'reused' : null,
    async () => { report.strings = await sampleStrings(blob, progress); });
  await job('sha256', 'Hashing the active file', node, report.sha256 ? 'reused' : blob.size > maxExpanded ? 'sizeLimit' : null,
    async () => { report.sha256 = await sha256(blob, progress); });
  const isZip = report.format === 'ZIP';
  await job('zipLayout', 'Checking ZIP layout', node, !isZip ? 'notApplicable' : report.zipChecks ? 'reused' : null,
    () => zipChecks(node, progress));
  await job('zipCrc32', 'Verifying ZIP entry CRC32', node, !isZip ? 'notApplicable' : report.zipChecks?.integrity ? 'reused' : null,
    () => zipChecks(node, progress, true));
  await job('inventory', 'Indexing the root archive', root,
    !archiveFormat(root.report.format) ? 'notApplicable' : inventory ? 'reused' : null,
    async () => { inventory = await buildInventory(root, progress); });
  session.retainFile(node);
  progress({ stage: 'Assembling the full report' });
  const payload = session.snapshot(root, node, automatic, inventory);
  progress({ stage: 'Serializing JSON' });
  const output = new Blob([JSON.stringify(payload), '\n'], { type: 'application/json' });
  return {
    output, name: root.report.name, files: payload.files.length, operations: payload.operations.length,
    warnings: automatic.filter(task => task.status === 'error' || task.status === 'sizeLimit').length,
    omitted: payload.omitted.files + payload.omitted.operations,
    updates: { strings: report.strings, sha256: report.sha256, zipChecks: report.zipChecks },
    ...(inventory && !existingInventory ? { inventory } : {})
  };
}

async function run({ action, file, index, offset, query, mode, nested }, progress) {
  switch (action) {
    case 'open': {
      const node = await inspect(file, file.name, undefined, progress);
      node.route = [];
      node.path = [node.report.name];
      stack.splice(0, stack.length, node);
      inventory = undefined;
      bytePair = undefined;
      session = createReportSession();
      return listing();
    }
    case 'member':
      await appendMember(stack, index, progress);
      session.retainFile(current());
      bytePair = undefined;
      return listing();
    case 'ancestor':
      if (!Number.isInteger(index) || index < 0 || index >= stack.length) throw new Error('That parent is not open.');
      stack.splice(index + 1);
      bytePair = undefined;
      return listing();
    case 'parent':
      if (stack.length > 1) {
        stack.pop();
        bytePair = undefined;
      }
      return listing();
    case 'inventory':
      current();
      inventory = await buildInventory(stack[0], progress);
      return inventory;
    case 'inventory-open': {
      const record = inventory?.rows[index];
      if (!record?.open) throw new Error('That inventory entry cannot be opened.');
      const next = [stack[0]];
      for (const entryIndex of record.route) await appendMember(next, entryIndex, progress);
      stack.splice(0, stack.length, ...next);
      for (const node of next) session.retainFile(node);
      bytePair = undefined;
      return listing();
    }
    case 'full-report': return fullReport(progress);
    case 'diff-bytes': {
      const left = current();
      const candidate = file ?? bytePair?.after;
      if (!candidate) throw new Error('Choose a candidate file first.');
      const result = await compareBytes(left.blob, candidate, offset, progress);
      bytePair = { before: left.blob, after: candidate };
      return session.record(left, 'byteDiff', {
        ...result, schema: 'gameautopsy/byte-diff/1', before: left.report.name, after: candidate.name, path: left.path
      });
    }
    case 'diff-preview': {
      if (!bytePair) throw new Error('Compare two files first.');
      const result = await previewDiff(bytePair.before, bytePair.after, offset);
      return session.record(current(), 'byteDiffPreview', result, { candidate: bytePair.after.name });
    }
    case 'compare': {
      const before = current();
      const after = await inspect(file, file.name, undefined, progress);
      const result = compareArchives(before.report, after.report);
      if (nested) result.nested = await compareNestedArchives(before, after, result, progress);
      return session.record(before, 'archiveComparison', result, { nested });
    }
    case 'checks': {
      const node = current();
      return session.record(node, 'zipLayout', await zipChecks(node, progress, false, true));
    }
    case 'verify-zip': {
      const node = current();
      return session.record(node, 'zipCrc32', await zipChecks(node, progress, true));
    }
    case 'download': {
      if (stack.length <= 1) throw new Error('Open an archive member first.');
      return current().blob;
    }
    case 'search-bytes': {
      const node = current();
      return session.record(node, 'byteSearch', await searchBytes(node.blob, query, mode, offset, progress), { query, mode });
    }
    case 'hex': {
      const node = current();
      const result = await startHex(node.blob, offset);
      return session.record(node, 'hexPreview', result);
    }
    case 'strings': {
      const node = current();
      node.report.strings = await sampleStrings(node.blob, progress);
      return session.record(node, 'strings', node.report.strings);
    }
    case 'sha256': {
      const node = current();
      node.report.sha256 = await sha256(node.blob, progress);
      return session.record(node, 'sha256', node.report.sha256);
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

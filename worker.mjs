import { analyze, MiB, openUnityMember, openZipMember, preview, sampleStrings } from './formats.mjs?v=0.4.0';
import { compareArchives } from './compare.mjs?v=0.4.0';
import { compareNestedArchives } from './nested-compare.mjs';
import { checkZip, verifyZipPayloads } from './zip-checks.mjs';
import { searchBytes } from './byte-search.mjs';

const stack = [];
const maxDepth = 6;
const maxExpanded = 256 * MiB;

async function inspect(blob, name, source = null) {
  const report = await analyze(blob, name);
  if (source) report.source = source;
  return { blob, report };
}

function current() {
  if (!stack.length) throw new Error('Choose a file first.');
  return stack.at(-1);
}

function listing() {
  return {
    path: stack.map(node => node.report.name),
    report: current().report
  };
}

async function run({ action, file, index, offset, query, mode, nested }) {
  switch (action) {
    case 'open':
      stack.splice(0, stack.length, await inspect(file, file.name));
      return listing();
    case 'member': {
      const { blob, report } = current();
      const entry = report.rows[index];
      if (!entry?.open) throw new Error('That entry cannot be opened.');
      if (stack.length >= maxDepth + 1) throw new Error('The six-level nesting limit has been reached.');
      const retained = stack.slice(1).reduce((sum, node) => sum + node.blob.size, 0);
      if (retained + entry.size > maxExpanded) throw new Error('Open entries would exceed the combined 256 MiB limit.');
      if (report.format === 'UnityFS') {
        const member = await openUnityMember(blob, report, entry);
        stack.push(await inspect(member, entry.name, { streamOffset: entry.streamOffset }));
      } else if (report.format === 'Godot PCK') {
        if (entry.size > 128 * MiB) throw new Error('The PCK file exceeds the 128 MiB open limit.');
        const member = blob.slice(entry.offset, entry.offset + entry.size);
        stack.push(await inspect(member, entry.name, { dataOffset: entry.offset, declaredMd5: entry.declaredMd5 }));
      } else {
        const opened = await openZipMember(blob, entry);
        stack.push(await inspect(opened.blob, entry.name, {
          localHeaderOffset: entry.offset, dataOffset: opened.dataOffset, crc32: entry.crc32
        }));
      }
      return listing();
    }
    case 'parent':
      if (stack.length > 1) stack.pop();
      return listing();
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
    self.postMessage({ id, data: await run(event.data) });
  } catch (error) {
    self.postMessage({ id, error: error.message });
  }
});

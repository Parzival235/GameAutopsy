import { analyze, MiB, openZipMember, preview, sampleStrings } from './formats.mjs?v=0.2.0';
import { compareArchives } from './compare.mjs';

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

async function run({ action, file, index, offset }) {
  switch (action) {
    case 'open':
      stack.splice(0, stack.length, await inspect(file, file.name));
      return listing();
    case 'member': {
      const { blob, report } = current();
      const entry = report.rows[index];
      if (report.format !== 'ZIP' || !entry?.open) throw new Error('That ZIP entry cannot be opened.');
      if (stack.length >= maxDepth + 1) throw new Error('The six-level nesting limit has been reached.');
      const retained = stack.slice(1).reduce((sum, node) => sum + node.blob.size, 0);
      if (retained + entry.size > maxExpanded) throw new Error('Open entries would exceed the combined 256 MiB limit.');
      const opened = await openZipMember(blob, entry);
      stack.push(await inspect(opened.blob, entry.name, {
        localHeaderOffset: entry.offset, dataOffset: opened.dataOffset, crc32: entry.crc32
      }));
      return listing();
    }
    case 'parent':
      if (stack.length > 1) stack.pop();
      return listing();
    case 'compare': {
      // Read only the candidate's ZIP directory, without touching workspace state.
      const candidate = await analyze(file, file.name);
      return compareArchives(current().report, candidate);
    }
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

import { analyze, MiB, openUnityMember, openZipMember } from './formats.mjs?v=0.13.0';

export const maxDepth = 6;
export const maxExpanded = 256 * MiB;
export const maxMember = 128 * MiB;

export const archiveFormat = format => ['ZIP', 'UnityFS', 'Godot PCK'].includes(format);

export async function inspect(blob, name, source, progress) {
  const report = await analyze(blob, name, progress);
  if (source) report.source = source;
  return { blob, report };
}

export async function readMember(parent, entry, progress = () => {}, charge = () => {}) {
  if (!entry?.open) throw new Error('That entry cannot be opened.');
  if (entry.size > maxMember) throw new Error('The entry exceeds the 128 MiB open limit.');
  const { blob, report } = parent;
  progress({ stage: 'Opening ' + entry.name });
  switch (report.format) {
    case 'UnityFS':
      return { blob: await openUnityMember(blob, report, entry, charge), source: { streamOffset: entry.streamOffset } };
    case 'Unity serialized file':
      charge(entry.size);
      return { blob: blob.slice(entry.offset, entry.offset + entry.size), source: {
        dataOffset: entry.offset, pathId: entry.pathId, classId: entry.classId
      } };
    case 'Godot PCK':
      charge(entry.size);
      return { blob: blob.slice(entry.offset, entry.offset + entry.size), source: {
        dataOffset: entry.offset, declaredMd5: entry.declaredMd5
      } };
    case 'ZIP': {
      charge(entry.packed + entry.size);
      const opened = await openZipMember(blob, entry, progress);
      return { blob: opened.blob, source: {
        localHeaderOffset: entry.offset, dataOffset: opened.dataOffset, crc32: entry.crc32
      } };
    }
    default: throw new Error('That format has no openable entries.');
  }
}

export async function openMember(parent, entry, progress = () => {}, charge) {
  const { blob, source } = await readMember(parent, entry, progress, charge);
  const name = parent.report.format === 'Unity serialized file' ? entry.name + '.bin' : entry.name;
  return inspect(blob, name, source, progress);
}

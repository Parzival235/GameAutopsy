import { analyze, MiB, openUnityMember, openZipMember } from './formats.mjs?v=0.5.0';

export const maxDepth = 6;
export const maxExpanded = 256 * MiB;
export const maxMember = 128 * MiB;

export const archiveFormat = format => ['ZIP', 'UnityFS', 'Godot PCK'].includes(format);

export async function inspect(blob, name, source) {
  const report = await analyze(blob, name);
  if (source) report.source = source;
  return { blob, report };
}

export async function openMember(parent, entry) {
  if (!entry?.open) throw new Error('That entry cannot be opened.');
  if (entry.size > maxMember) throw new Error('The entry exceeds the 128 MiB open limit.');
  const { blob, report } = parent;
  switch (report.format) {
    case 'UnityFS':
      return inspect(await openUnityMember(blob, report, entry), entry.name, { streamOffset: entry.streamOffset });
    case 'Godot PCK':
      return inspect(blob.slice(entry.offset, entry.offset + entry.size), entry.name, {
        dataOffset: entry.offset, declaredMd5: entry.declaredMd5
      });
    case 'ZIP': {
      const opened = await openZipMember(blob, entry);
      return inspect(opened.blob, entry.name, {
        localHeaderOffset: entry.offset, dataOffset: opened.dataOffset, crc32: entry.crc32
      });
    }
    default: throw new Error('That format has no openable entries.');
  }
}

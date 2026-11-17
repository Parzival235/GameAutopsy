import { MiB } from './formats.mjs?v=0.14.0';
import { archiveFormat, maxMember, openMember } from './archive-members.mjs?v=0.14.0';

const maxDepth = 4;
const maxContainers = 48;
const maxEntries = 24000;
const maxText = 4 * MiB;
const maxBytes = 256 * MiB;
const candidateName = /\.(?:zip|apk|apks|xapk|aab|ipa|obb|pck|bundle|unity3d|assetbundle|ab)$/i;
const category = name => {
  const ext = name.match(/\.([^.\/\\]+)$/)?.[1]?.toLowerCase();
  if (candidateName.test(name)) return 'Archive candidate';
  if (/^(dex|so|dll|exe|wasm|dylib|gdc)$/.test(ext)) return 'Code / binary';
  if (/^(yaml|yml|json|xml|ini|cfg|toml|csv|lua|gd|js|txt|tscn|tres)$/.test(ext)) return 'Text / data';
  if (/^(png|jpe?g|webp|bmp|dds|ktx2?|ogg|wav|mp3|flac|mp4|webm)$/.test(ext)) return 'Media';
  return 'Other';
};

function memberRow(format, row) {
  if (format === 'ZIP') return row.kind !== 'Directory';
  if (format === 'UnityFS') return row.kind === 'UnityFS file';
  return format === 'Godot PCK' && row.recordOffset != null;
}

export async function buildInventory(root, onProgress = () => {}) {
  if (!archiveFormat(root.report.format)) throw new Error('Open a ZIP, UnityFS or Godot PCK package first.');
  const result = {
    schema: 'gameautopsy/inventory/1', root: root.report.name, format: root.report.format,
    rows: [], notices: [], containers: 1, attempted: 0, bytesBudgeted: 0, skipped: 0, truncated: false
  };
  let textBudget = maxText;

  function skip(path, reason) {
    result.skipped++;
    if (result.notices.length < 50) result.notices.push({ path: path.map(s => s.slice(0, 256)), reason });
  }

  async function walk(parent, names, route) {
    const { report } = parent;
    if (report.status !== 'ok' || report.warnings.length) {
      skip(names, report.warnings[0] ?? 'Only a partial directory was available.');
    }
    const candidates = [];
    for (const [index, row] of report.rows.entries()) {
      if (!memberRow(report.format, row)) continue;
      if (result.rows.length === maxEntries || row.name.length > textBudget) {
        result.truncated = true;
        skip(names, 'The entry or path text budget was reached.');
        break;
      }
      textBudget -= row.name.length;
      const record = {
        id: result.rows.length, name: row.name, path: names, route: [...route, index],
        kind: row.kind, category: category(row.name), size: row.size, open: Boolean(row.open),
        offset: row.offset, streamOffset: row.streamOffset, packed: row.packed, crc32: row.crc32
      };
      result.rows.push(record);
      if (record.category === 'Archive candidate') candidates.push({ row, record });
    }
    for (const { row, record } of candidates) {
      if (result.truncated) break;
      const path = [...names, row.name];
      const cost = (row.packed ?? row.size) + row.size;
      if (!record.open || !Number.isSafeInteger(cost) || row.size > maxMember ||
          Math.max(row.packed ?? 0, row.size) > maxMember || record.route.length > maxDepth ||
          result.attempted >= maxContainers - 1 || cost > maxBytes - result.bytesBudgeted) {
        skip(path, 'Member is unavailable or exceeds an inventory limit.');
        continue;
      }
      result.attempted++;
      result.bytesBudgeted += cost;
      onProgress({ stage: 'Indexing nested archives', detail: result.rows.length + ' entries indexed · ' +
        result.containers + ' containers found' });
      let child;
      try {
        child = await openMember(parent, row);
      } catch (error) {
        skip(path, error.message);
        continue;
      }
      record.detectedFormat = child.report.format;
      if (!archiveFormat(child.report.format)) {
        skip(path, 'The member did not parse as a supported archive.');
        continue;
      }
      result.containers++;
      await walk(child, path, record.route);
    }
  }
  await walk(root, [root.report.name], []);
  onProgress({ stage: 'Inventory ready', detail: result.rows.length + ' entries indexed · ' + result.containers + ' containers found' });
  return result;
}

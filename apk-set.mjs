import { analyze, MiB, openZipMember, zipLocalInfo } from './formats.mjs?v=0.10.0';
import { declaredApkSigners } from './apk-certs.mjs';
import { parseBundletoolToc } from './bundletool-toc.mjs';

const maxApks = 128;
const maxExpanded = 384 * MiB;
const maxFindings = 1000;
const maxNativePaths = 256;
const engineLibraries = new Set(['libil2cpp.so', 'libunity.so', 'libgodot_android.so', 'libUnreal.so', 'libUE4.so']);
const isApk = name => /\.apk$/i.test(name);
const isSetName = name => /\.(apks|xapk|apkm)$/i.test(name);
const apkPaths = report => report.rows.filter(row => isApk(row.name) && row.kind !== 'Directory');
const completeDirectory = report => report.format === 'ZIP' && report.status === 'ok' &&
  report.rows.length === report.details['Declared entries'];
const leafName = name => name.split('/').at(-1);

export function canInspectApkSet(report) {
  return report.format === 'ZIP' && (
    isApk(report.name) || isSetName(report.name) || report.rows.some(row => row.name === 'AndroidManifest.xml' || isApk(row.name))
  );
}

function manifestVersion(manifest) {
  if (manifest.versionCode == null && manifest.versionCodeMajor == null) return '0';
  const number = value => {
    const n = value ?? 0;
    if (typeof n === 'string' && !/^(?:\d+|0x[\da-f]+)$/i.test(n)) throw new Error('Unresolved version code.');
    const value32 = BigInt(n);
    if (value32 < 0n || value32 > 0xffffffffn) throw new Error('Version code exceeds uint32.');
    return value32;
  };
  return ((number(manifest.versionCodeMajor) << 32n) | number(manifest.versionCode)).toString();
}

async function readManifest(blob, report) {
  const manifests = report.rows.filter(row => row.name === 'AndroidManifest.xml');
  if (manifests.length !== 1) throw new Error(manifests.length ? 'Duplicate AndroidManifest.xml entries.' : 'AndroidManifest.xml is missing.');
  const [entry] = manifests;
  if (Math.max(entry.size, entry.packed) > 2 * MiB) throw new Error('Android manifest exceeds the 2 MiB read limit.');
  const { blob: xml } = await openZipMember(blob, entry);
  const result = await analyze(xml, 'AndroidManifest.xml');
  if (result.format !== 'Android binary XML' || result.status !== 'ok' || result.warnings.length ||
      typeof result.manifest?.package !== 'string' || !result.manifest.package) {
    throw new Error(result.warnings[0] ?? 'Android binary manifest and package name could not be read.');
  }
  const manifest = result.manifest;
  if (manifest.split != null && typeof manifest.split !== 'string') throw new Error('Invalid manifest split ID.');
  return { ...manifest, longVersionCode: manifestVersion(manifest) };
}

async function details(blob, report, record) {
  if (!completeDirectory(report)) throw new Error('APK central directory could not be read completely.');
  record.manifest = await readManifest(blob, report);
  const { manifest } = record;
  record.role = !manifest.split ? 'Base or standalone' : manifest.isFeatureSplit === true ? 'Feature' :
    manifest.configForSplit != null || /(?:^|\.)config\./.test(manifest.split) ? 'Configuration' : 'Split';
  const abis = new Set();
  const engines = new Set();
  record.native = [];
  record.nativeCount = 0;
  record.dex = [];
  for (const row of report.rows) {
    const match = /^lib\/([^/]+)\/([^/]+\.so)$/.exec(row.name);
    if (match) {
      abis.add(match[1]);
      record.nativeCount++;
      if (engineLibraries.has(match[2])) engines.add(match[2]);
      if (record.native.length < maxNativePaths) {
        record.native.push({ abi: match[1], name: match[2], path: row.name, size: row.size });
      }
    }
    if (/^classes(?:[2-9]|[1-9]\d+)?\.dex$/.test(row.name) && record.dex.length < 128) record.dex.push(row.name);
  }
  record.abis = [...abis].sort();
  record.engines = [...engines].sort();
  try {
    record.signing = await declaredApkSigners(blob, report);
  } catch (error) {
    record.signing = { status: 'unreadable', schemes: [], error: error.message };
  }
}

async function memberForInspection(blob, entry) {
  if (!entry.open) throw new Error('APK member cannot be opened with this compression or encryption.');
  if (entry.method !== 0) {
    const { blob: member } = await openZipMember(blob, entry);
    return { member, outerCrc: 'verified' };
  }
  // Stored APKs can be read by range without pulling their entire payload into memory.
  const start = await zipLocalInfo(blob, entry);
  return { member: blob.slice(start, start + entry.packed), outerCrc: 'notChecked' };
}

function signersByScheme(record) {
  const groups = new Map();
  for (const scheme of record.signing?.schemes ?? []) {
    if (scheme.error) continue;
    for (const signer of scheme.signers) {
      const key = scheme.name + (signer.sdk ? ' SDK ' + signer.sdk.min + '–' + signer.sdk.max : '');
      const list = groups.get(key) ?? [];
      list.push(signer.certificateSha256);
      groups.set(key, list);
    }
  }
  for (const [key, list] of groups) groups.set(key, list.sort().join(','));
  return groups;
}

const splitTypes = value => typeof value === 'string' && !value.startsWith('@') ? value.split(',').map(text => text.trim()).filter(Boolean) : [];

export function checkApkGroup(group, items, options = {}) {
  const { expectedPackage, complete = true, modules = [], abi = '' } = options;
  const findings = [];
  const add = (level, code, path, message) => {
    if (findings.length < maxFindings) findings.push({ level, code, path, message });
  };
  const apks = items.filter(record => record.manifest);
  const observed = new Set(apks.map(record => record.manifest.split).filter(Boolean));
  const bases = apks.filter(record => !record.manifest.split);
  if (!apks.length) return [{ level: 'Unknown', code: 'manifestCoverage', path: group, message: 'No readable APK manifest is available.' }];
  if (!complete) add('Unknown', 'manifestCoverage', group, 'Some APK paths or manifests were unreadable or outside scan limits.');
  if (!bases.length) {
    add(complete ? 'Error' : 'Unknown', 'missingBase', group, 'No base APK was found in the inspected set.');
  }
  if (bases.length > 1) {
    add('Unknown', 'multipleBases', group, 'Multiple base APKs without a usable variant boundary. They may be alternatives.');
    return findings;
  }
  const base = bases[0];
  const packageName = base?.manifest.package ?? expectedPackage;
  const version = base?.manifest.longVersionCode;
  const expectedSigners = base ? signersByScheme(base) : new Map();
  const dedup = new Set();
  const availableTypes = new Set(apks.flatMap(record => splitTypes(record.manifest.splitTypes)));
  const moduleNames = new Set(modules.map(module => module.name).filter(Boolean));
  if (expectedPackage && base && base.manifest.package !== expectedPackage) {
    add('Error', 'tocPackageMismatch', base.path, 'TOC package ' + expectedPackage + ' disagrees with base package ' + base.manifest.package + '.');
  }
  for (const record of apks) {
    const { manifest, path } = record;
    if (packageName && manifest.package !== packageName) add('Error', 'packageMismatch', path, 'Expected package ' + packageName + ' but found ' + manifest.package + '.');
    if (version != null && manifest.longVersionCode !== version) add('Error', 'versionMismatch', path, 'Expected version code ' + version + ' but found ' + manifest.longVersionCode + '.');
    if (manifest.split && dedup.has(manifest.split)) add('Warning', 'duplicateSplit', path, 'Split ID ' + manifest.split + ' occurs more than once. Check device targeting.');
    if (manifest.split) dedup.add(manifest.split);
    for (const dependency of new Set([manifest.configForSplit, ...(manifest.usesSplits ?? [])].filter(Boolean))) {
      if (dependency !== 'base' && !observed.has(dependency)) {
        add(complete ? 'Error' : 'Unknown', 'missingDependency', path, 'Required split ' + dependency + ' was not found.');
      }
    }
    for (const type of splitTypes(manifest.requiredSplitTypes)) {
      if (!availableTypes.has(type)) add(complete ? 'Error' : 'Unknown', 'missingSplitType', path, 'Required split type ' + type + ' was not found.');
    }
    if (record === base) continue;
    const common = [...signersByScheme(record)].filter(([key]) => expectedSigners.has(key));
    if (!common.length) add('Unknown', 'signerUnavailable', path, 'No comparable declared signer certificate and SDK range.');
    for (const [scheme, hashes] of common) {
      if (expectedSigners.get(scheme) !== hashes) add('Warning', 'signerMismatch', path, 'Declared certificate SHA-256 differs from base for ' + scheme + '.');
    }
  }
  if (base?.manifest.isSplitRequired === true && !observed.size) {
    add(complete ? 'Error' : 'Unknown', 'splitsRequired', base.path, 'Base declares splits required but no split was found.');
  }
  for (const module of modules) {
    for (const dependency of module.dependencies) {
      if (dependency !== 'base' && !moduleNames.has(dependency)) {
        add(complete ? 'Error' : 'Unknown', 'missingModule', module.name, 'TOC dependency ' + dependency + ' is absent from this variant.');
      }
    }
  }
  if (abi && apks.some(record => record.abis.length) && !apks.some(record => record.abis.includes(abi))) {
    add(complete ? 'Warning' : 'Unknown', 'abiUnavailable', group, 'No native libraries for ' + abi + ' were observed across these APKs.');
  }
  return findings;
}

export async function inspectApkSet(root, abi = '', progress = () => {}) {
  const { blob, report } = root;
  if (!canInspectApkSet(report)) throw new Error('Open an APK or an APK set first.');
  const result = {
    schema: 'gameautopsy/apk-set/1', name: report.name, abi: abi || null, package: null,
    source: 'manifest', items: [], groups: [], findings: [], skipped: 0, declared: 0
  };
  const add = (level, code, path, message) => {
    if (result.findings.length < maxFindings) result.findings.push({ level, code, path, message });
  };
  const entries = apkPaths(report);
  const byPath = new Map();
  const duplicatePaths = new Set();
  for (const entry of entries) {
    if (byPath.has(entry.name)) duplicatePaths.add(entry.name);
    byPath.set(entry.name, entry);
  }
  for (const path of duplicatePaths) add('Error', 'duplicatePath', path, 'Duplicate APK path in archive.');
  const byToc = report.rows.filter(row => row.name === 'toc.pb');
  const xapk = /\.xapk$/i.test(report.name);
  let toc;
  let expectedXapk = [];
  try {
    if (byToc.length > 1) throw new Error('Multiple toc.pb entries.');
    if (byToc.length) {
      const [entry] = byToc;
      if (Math.max(entry.size, entry.packed) > 4 * MiB) throw new Error('toc.pb exceeds 4 MiB.');
      const { blob: tocBlob } = await openZipMember(blob, entry);
      toc = parseBundletoolToc(new Uint8Array(await tocBlob.arrayBuffer()));
      result.source = 'bundletool toc.pb';
      result.package = toc.package || null;
    } else if (xapk) {
      const manifests = report.rows.filter(row => row.name === 'manifest.json');
      if (manifests.length > 1) throw new Error('Multiple XAPK manifest.json entries.');
      if (manifests.length) {
        const [entry] = manifests;
        if (Math.max(entry.size, entry.packed) > MiB) throw new Error('XAPK manifest exceeds 1 MiB.');
        const { blob: text } = await openZipMember(blob, entry);
        const manifest = JSON.parse(await text.text());
        if (manifest && Array.isArray(manifest.split_apks)) expectedXapk = manifest.split_apks
          .map(row => row?.file).filter(file => typeof file === 'string' && file.length <= 4096 && isApk(file));
        result.source = 'XAPK manifest + APK manifests';
        result.package = typeof manifest?.package_name === 'string' ? manifest.package_name.slice(0, 4096) : null;
      }
    }
  } catch (error) {
    add('Unknown', 'setMetadata', byToc.length ? 'toc.pb' : 'manifest.json', error.message);
  }
  const standalone = report.rows.some(row => row.name === 'AndroidManifest.xml') || (isApk(report.name) && !entries.length);
  const candidates = standalone ? [{ path: report.name, root: true }] :
    [...byPath.entries()].map(([path, entry]) => ({ path, entry }));
  candidates.sort((a, b) => (leafName(a.path) === 'base.apk' ? 0 : 1) - (leafName(b.path) === 'base.apk' ? 0 : 1));
  result.declared = candidates.length;
  if (!candidates.length) add('Unknown', 'noApks', report.name, 'No APK members were found in the ZIP directory.');
  const parentComplete = completeDirectory(report);
  if (!parentComplete) add('Unknown', 'directoryCoverage', report.name, 'The root ZIP directory was not fully read.');
  const rowIndices = new Map(report.rows.map((row, index) => [row, index]));
  let budget = maxExpanded;
  const records = new Map();
  for (const [index, { path, entry, root: plain }] of candidates.entries()) {
    if (index >= maxApks) {
      result.skipped += candidates.length - index;
      add('Unknown', 'apkLimit', report.name, candidates.length - index + ' APKs exceed the 128-entry scan limit.');
      break;
    }
    const record = { path, entryIndex: !plain && entry.size <= 128 * MiB && entry.packed <= 128 * MiB &&
      entry.open && !duplicatePaths.has(path) ? rowIndices.get(entry) : null };
    result.items.push(record);
    records.set(path, record);
    progress({ stage: 'Inspecting APK manifests', done: index, total: Math.min(candidates.length, maxApks), unit: 'APKs', detail: path });
    try {
      if (duplicatePaths.has(path)) throw new Error('Ambiguous APK path.');
      if (plain) await details(blob, report, record);
      else {
        if (entry.method !== 0) {
          const cost = entry.size + entry.packed;
          if (cost > budget) throw new Error('Compressed APK exceeds the remaining expansion budget.');
          budget -= cost;
        }
        const { member, outerCrc } = await memberForInspection(blob, entry);
        record.outerCrc = outerCrc;
        await details(member, await analyze(member, path), record);
      }
    } catch (error) {
      record.error = error.message;
      result.skipped++;
      add('Unknown', 'apkUnreadable', path, error.message);
    }
  }
  progress({ stage: 'Checking APK set dependencies', done: result.items.length, total: Math.min(candidates.length, maxApks), unit: 'APKs' });
  for (const path of new Set(expectedXapk)) {
    if (!byPath.has(path)) add(parentComplete ? 'Error' : 'Unknown', 'missingArchiveMember', path, 'APK named in XAPK manifest is missing.');
  }
  const groups = result.groups;
  let groupLimit = false;
  const described = new Set();
  const makeGroup = (label, apks, options = {}) => {
    const paths = [...new Set(apks.map(apk => apk.path))];
    if (groups.length === maxApks) {
      if (!groupLimit) add('Unknown', 'groupLimit', report.name, 'Variant reporting stopped at 128 groups.');
      groupLimit = true;
      return;
    }
    const group = { label, paths, ...(options.modules ? { modules: options.modules } : {}) };
    groups.push(group);
    for (const path of paths) {
      described.add(path);
      if (toc && !byPath.has(path)) add(parentComplete ? 'Error' : 'Unknown', 'missingArchiveMember', path, 'APK named in ' + label + ' is missing.');
    }
    if (options.compare === false) return;
    const items = paths.map(path => records.get(path)).filter(Boolean);
    const complete = parentComplete && items.filter(row => row.manifest).length === paths.length;
    const defects = checkApkGroup(label, items, { ...options, expectedPackage: result.package, complete, abi });
    group.findingCounts = Object.fromEntries(['Error', 'Warning', 'Unknown'].map(level =>
      [level, defects.filter(item => item.level === level).length]));
    for (const found of defects) {
      if (result.findings.length === maxFindings) break;
      result.findings.push({ ...found, group: label });
    }
  };
  if (toc) {
    for (const [index, variant] of toc.variants.entries()) {
      const label = 'Variant ' + variant.number + ' (#' + (index + 1) + ')';
      const apks = variant.modules.flatMap(module => module.apks);
      const splits = apks.filter(apk => apk.kind === 'split');
      if (splits.length) makeGroup(label, splits, { modules: variant.modules.map(({ name, dependencies }) => ({ name, dependencies })) });
      for (const apk of apks.filter(apk => apk.kind === 'standalone')) makeGroup(label + ' / ' + apk.path, [apk]);
      const other = apks.filter(apk => apk.kind === 'other');
      if (other.length) makeGroup(label + ' / other delivery', other, { compare: false });
    }
    if (toc.assetSlices.length) makeGroup('Asset slices', toc.assetSlices.map(path => ({ path })), { compare: false });
    const unlisted = candidates.filter(candidate => !described.has(candidate.path));
    if (unlisted.length) {
      add('Info', 'notInToc', report.name, unlisted.length + ' APKs are not listed in parsed TOC groups.');
      makeGroup('Unlisted APKs', unlisted, { compare: false });
    }
  } else if (candidates.length) {
    makeGroup(standalone ? 'Single APK' : 'Archive APKs', candidates);
  }
  result.package ??= result.items.find(item => item.manifest && !item.manifest.split)?.manifest.package ?? null;
  result.inspected = result.items.filter(item => item.manifest).length;
  result.abis = [...new Set(result.items.flatMap(item => item.abis ?? []))].sort();
  result.findingsMayBeTruncated = result.findings.length === maxFindings;
  result.nativeFiles = result.items.flatMap(item => (item.engines ?? []).map(name => ({ apk: item.path, name })));
  return result;
}

import { interpretBytes } from './hex.mjs';

const byId = id => document.getElementById(id);
const pageSize = 80;
const digits = new Intl.NumberFormat('en-US');
const tabs = { structure: 'structure', hex: 'hex', compare: 'comparison', checks: 'checks', find: 'find', strings: 'strings' };
const worker = new Worker('./worker.mjs?v=0.4.0', { type: 'module' });
let current;
let page = 0;
let comparison;
let comparisonPage = 0;
let hexPage;
let highlighted;
let checkPage = 0;
let nextSearch;
let activeSearch;
let requestId = 0;
let busy = false;
let workerError;
const pending = new Map();

const hex = (number, width = 0) => number.toString(16).toUpperCase().padStart(width, '0');
const address = number => number == null ? '—' : '0x' + hex(number);
const bytes = number => number == null ? '—' : digits.format(number) + ' B';

worker.addEventListener('message', ({ data: { id, data, error } }) => {
  const callback = pending.get(id);
  if (!callback) return;
  pending.delete(id);
  if (error) callback.reject(new Error(error));
  else callback.resolve(data);
});
worker.addEventListener('error', () => {
  workerError = new Error('Could not start the file reader. Open the app over HTTPS or localhost.');
  for (const callback of pending.values()) callback.reject(workerError);
  pending.clear();
});

function call(action, args) {
  if (workerError) return Promise.reject(workerError);
  const id = ++requestId;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    try {
      worker.postMessage({ id, action, ...args });
    } catch (error) {
      pending.delete(id);
      reject(error);
    }
  });
}

function status(text, error = false) {
  byId('status').textContent = text;
  byId('status').classList.toggle('error', error);
}

async function perform(label, work) {
  if (busy) return;
  busy = true;
  byId('workspace').setAttribute('aria-busy', 'true');
  byId('choose').disabled = true;
  status(label);
  try {
    await work();
    status('');
  } catch (error) {
    status(error.message, true);
  } finally {
    busy = false;
    byId('choose').disabled = false;
    byId('workspace').setAttribute('aria-busy', 'false');
  }
}

function node(tag, text) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  return element;
}

function definitions(element, data) {
  element.replaceChildren(...Object.entries(data).map(([key, value]) => {
    const cell = node('div');
    cell.append(node('dt', key), node('dd', String(value)));
    return cell;
  }));
}

function actionButton(label, callback) {
  const btn = node('button', label);
  btn.className = 'secondary';
  btn.addEventListener('click', callback);
  return btn;
}

function summarize(e) {
  const values = [];
  if (e.packed != null) values.push('Packed ' + bytes(e.packed), 'CRC32 ' + hex(e.crc32, 8), 'CD ' + address(e.central));
  if (e.count != null) values.push(digits.format(e.count) + ' entries');
  if (e.address != null) values.push(e.address);
  if (e.line != null) values.push('Line ' + e.line);
  if (e.logicalIndex != null) values.push('DEX #' + (e.logicalIndex + 1));
  if (e.streamOffset != null) values.push('Decoded offset ' + address(e.streamOffset));
  if (e.declaredMd5) values.push('MD5 ' + e.declaredMd5);
  if (e.note != null) values.push(e.note);
  return values.join(' · ') || '—';
}

function renderRows() {
  const query = byId('search').value.trim().toLocaleLowerCase();
  const matches = [];
  for (const [index, entry] of current.report.rows.entries()) {
    if (!query || [entry.name, entry.kind, address(entry.offset), String(entry.offset), summarize(entry)]
      .some(value => value.toLocaleLowerCase().includes(query))) matches.push({ index, entry });
  }
  const last = Math.max(0, Math.ceil(matches.length / pageSize) - 1);
  page = Math.min(page, last);
  const rows = matches.slice(page * pageSize, (page + 1) * pageSize).map(({ index, entry }) => {
    const tr = node('tr');
    for (const value of [entry.name, entry.kind, address(entry.offset), bytes(entry.size), summarize(entry)]) {
      tr.append(node('td', value));
    }
    const actions = node('td');
    if (entry.open) actions.append(actionButton('Open', () =>
      perform('Opening archive entry…', async () => show(await call('member', { index })))
    ));
    if (entry.offset != null && entry.offset < current.report.size) {
      actions.append(actionButton('Hex', () =>
        jumpTo(entry.offset, entry.packed == null ? entry.size : Math.min(entry.directoryOffset - entry.offset, 30))
      ));
    }
    if (entry.recordOffset != null) {
      actions.append(actionButton('Record', () => jumpTo(entry.recordOffset, entry.recordSize)));
    }
    tr.append(actions);
    return tr;
  });
  if (!rows.length) {
    const tr = node('tr');
    const cell = node('td', current.report.rows.length ? 'No matching entries.' : 'No structure table is available for this format.');
    cell.colSpan = 6;
    tr.append(cell);
    rows.push(tr);
  }
  byId('rows').replaceChildren(...rows);
  byId('count').textContent = digits.format(matches.length) + ' entries';
  byId('page').textContent = (page + 1) + ' / ' + (last + 1);
  byId('pages').hidden = last === 0;
  byId('prev').disabled = page === 0;
  byId('next').disabled = page === last;
}

function jumpTo(offset, length = 0) {
  return perform('Reading bytes…', async () => {
    await showHex(offset, length > 0 ? { start: offset, end: offset + length } : null);
    setTab('hex', true);
  });
}

function setTab(tab, focus = false) {
  for (const [name, panel] of Object.entries(tabs)) {
    const button = byId('tab-' + name);
    const selected = name === tab;
    button.setAttribute('aria-selected', String(selected));
    button.tabIndex = selected ? 0 : -1;
    byId(panel).hidden = !selected;
    if (selected && focus) button.focus();
  }
}

function show(data) {
  current = data;
  const { path, report } = current;
  const { source, details } = report;
  byId('path').textContent = path.length > 1 ? path.slice(0, -1).join(' › ') : 'Root file';
  byId('filename').textContent = report.name;
  byId('parent').hidden = path.length === 1;
  byId('compare').hidden = report.format !== 'ZIP';
  byId('nested-option').hidden = report.format !== 'ZIP';
  byId('tab-checks').hidden = report.format !== 'ZIP';
  byId('download-member').hidden = path.length === 1;
  checkPage = 0;
  updateChecks();
  byId('find-start').value = '0x0';
  byId('find-results').replaceChildren();
  byId('find-info').textContent = 'Search up to 64 MiB per pass. Use ?? to match one byte.';
  byId('find-more').hidden = true;
  nextSearch = null;
  byId('tab-compare').hidden = true;
  comparison = undefined;
  hexPage = undefined;
  highlighted = null;
  definitions(byId('stats'), {
    'Format': report.format, 'Size': bytes(report.size),
    'Structure rows': digits.format(report.rows.length),
    'Status': report.status === 'ok' && !report.warnings.length ? 'Parsed' : 'See warnings below'
  });
  definitions(byId('details'), {
    ...details,
    ...(source?.localHeaderOffset != null ? { 'Local header in parent': address(source.localHeaderOffset) } : {}),
    ...(source?.dataOffset != null ? { 'Data in parent': address(source.dataOffset) } : {}),
    ...(source?.declaredMd5 ? { 'Declared MD5 in parent': source.declaredMd5 } : {}),
    ...(source?.streamOffset != null ? { 'Decoded offset in parent': address(source.streamOffset) } : {})
  });
  byId('metadata').hidden = !Object.keys(details).length && !source;
  byId('warnings').replaceChildren(...report.warnings.map(message => node('li', message)));
  byId('warnings').hidden = !report.warnings.length;
  byId('search').value = '';
  byId('offset').value = '0x0';
  byId('hexview').textContent = '';
  byId('string-rows').replaceChildren();
  byId('string-info').textContent = '';
  byId('digest').textContent = '';
  page = 0;
  setTab('structure');
  renderRows();
  byId('workspace').hidden = false;
}

function renderInspector() {
  if (!hexPage) return;
  definitions(byId('values'), interpretBytes(hexPage.bytes, byId('endian').value === 'little'));
}

async function showHex(offset, selection = highlighted) {
  const data = await call('hex', { offset });
  hexPage = data;
  highlighted = selection;
  const show = byId('hexview');
  const out = document.createDocumentFragment();
  const mark = (text, position) => selection && position >= selection.start && position < selection.end ?
    node('mark', text) : document.createTextNode(text);
  for (let i = 0; i < data.bytes.length; i += 16) {
    const slice = data.bytes.slice(i, i + 16);
    out.append(hex(data.offset + i, 8) + '  ');
    for (const [index, byte] of slice.entries()) out.append(mark(hex(byte, 2), offset + i + index), ' ');
    out.append(' '.repeat((16 - slice.length) * 3 + 1));
    for (const [index, byte] of slice.entries()) {
      out.append(mark(byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.', offset + i + index));
    }
    out.append('\n');
  }
  byId('offset').value = address(offset);
  show.replaceChildren(data.bytes.length ? out : 'Empty file.');
  const end = offset + data.bytes.length;
  byId('hex-prev').disabled = offset === 0;
  byId('hex-next').disabled = end >= current.report.size;
  byId('hex-range').textContent = data.bytes.length ? address(offset) + '–' + address(end - 1) : '';
  renderInspector();
}

const comparisonLabels = {
  added: 'Added', removed: 'Removed', changed: 'Content metadata differs',
  repacked: 'Packing differs', moved: 'Offset differs', matched: 'Metadata matches',
  ambiguous: 'Duplicate path', encrypted: 'Encrypted entry'
};

function renderComparison() {
  const query = byId('comparison-search').value.trim().toLowerCase();
  const index = Number(byId('comparison-scope').value);
  const scope = index ? comparison.nested.groups[index - 1] : comparison;
  definitions(byId('comparison-stats'), Object.fromEntries(
    Object.entries(scope.counts).map(([key, count]) => [comparisonLabels[key], digits.format(count)])
  ));
  const matches = scope.rows.filter(row =>
    row.name.toLowerCase().includes(query) || comparisonLabels[row.status].toLowerCase().includes(query)
  );
  const last = Math.max(0, Math.ceil(matches.length / pageSize) - 1);
  comparisonPage = Math.min(comparisonPage, last);
  const items = matches.slice(comparisonPage * pageSize, (comparisonPage + 1) * pageSize);
  const rows = items.map(entry => {
    const tr = node('tr');
    const packed = group => group.length > 1 ? group.length + ' entries' : bytes(group[0]?.packed);
    const delta = entry.packedDelta > 0 ? '+' + bytes(entry.packedDelta) : bytes(entry.packedDelta);
    for (const value of [entry.name, comparisonLabels[entry.status], packed(entry.before), packed(entry.after), delta]) {
      tr.append(node('td', value));
    }
    return tr;
  });
  if (!rows.length) {
    const tr = node('tr');
    const cell = node('td', scope.rows.length ? 'No matching changes.' : 'No differences in compared metadata.');
    cell.colSpan = 5;
    tr.append(cell);
    rows.push(tr);
  }
  byId('comparison-rows').replaceChildren(...rows);
  byId('comparison-page').textContent = (comparisonPage + 1) + ' / ' + (last + 1);
  byId('comparison-pages').hidden = last === 0;
  byId('comparison-prev').disabled = comparisonPage === 0;
  byId('comparison-next').disabled = comparisonPage === last;
}

function showComparison(result) {
  comparison = result;
  comparison.path = current.path;
  comparisonPage = 0;
  byId('comparison-search').value = '';
  byId('comparison-path').textContent = result.baseline + ' → ' + result.candidate;
  const option = (title, value) => {
    const item = node('option', title);
    item.value = value;
    return item;
  };
  const nested = result.nested;
  const groups = nested?.groups ?? [];
  byId('comparison-scope-label').hidden = !groups.length;
  byId('comparison-scope').replaceChildren(option('Current archive', 0),
    ...groups.map((group, i) => option(group.path.join(' › '), i + 1)));
  byId('comparison-note').textContent = 'Comparison uses ZIP directory metadata. Matching sizes and CRC32 do not prove byte equality.';
  byId('comparison-notices').hidden = !nested;
  byId('comparison-notices').open = false;
  if (nested) {
    byId('comparison-notices-title').textContent = groups.length + ' nested pairs compared · ' +
      nested.matchingArchives + ' metadata matches not reopened · ' + nested.skipped + ' skipped';
    const notices = nested.notices.map(item => node('li', item.path.join(' › ') + ' — ' + item.reason));
    if (nested.skipped > notices.length) notices.push(node('li', 'Additional skipped paths are counted in the total.'));
    if (!notices.length) notices.push(node('li', 'No skipped archive paths besides metadata matches.'));
    byId('comparison-notice-list').replaceChildren(...notices);
  }
  renderComparison();
  byId('tab-compare').hidden = false;
  setTab('compare', true);
}

function updateChecks() {
  const report = current.report.zipChecks;
  byId('checks-output').hidden = !report;
  byId('checks-stats').replaceChildren();
  byId('checks-rows').replaceChildren();
  byId('check-pages').hidden = true;
  if (!report) return;
  const { integrity } = report;
  const findings = integrity ? [...report.checks, ...integrity.checks] : report.checks;
  definitions(byId('checks-stats'), {
    'Local headers checked': digits.format(report.localHeadersChecked),
    'Stored APK entries': digits.format(report.storedApkEntries),
    'Stored native libraries': digits.format(report.storedNativeLibraries),
    Findings: digits.format(findings.length),
    ...(integrity ? {
      'CRC32 verified': digits.format(integrity.verified),
      'CRC32 failed': digits.format(integrity.attempted - integrity.verified),
      'CRC32 skipped in report': digits.format(integrity.skipped),
      'Directory coverage': integrity.completeDirectory ? 'Complete' : 'Partial'
    } : {})
  });
  const pages = Math.max(1, Math.ceil(findings.length / pageSize));
  byId('check-pages').hidden = pages === 1;
  byId('check-page').textContent = (checkPage + 1) + ' / ' + pages;
  byId('check-prev').disabled = checkPage === 0;
  byId('check-next').disabled = checkPage + 1 >= pages;
  const rows = findings.slice(checkPage * pageSize, (checkPage + 1) * pageSize).map(finding => {
    const tr = node('tr');
    for (const value of [finding.status, finding.name, finding.message]) tr.append(node('td', value));
    const offset = node('td');
    if (finding.offset != null && finding.offset >= 0 && finding.offset < current.report.size) {
      offset.append(actionButton(address(finding.offset), () => jumpTo(finding.offset)));
    } else offset.textContent = '—';
    tr.append(offset);
    return tr;
  });
  if (!rows.length) {
    const tr = node('tr');
    const cell = node('td', 'No findings in the inspected layout.');
    cell.colSpan = 4;
    tr.append(cell);
    rows.push(tr);
  }
  byId('checks-rows').replaceChildren(...rows);
}

function parseOffset(raw) {
  const value = raw.trim();
  if (!/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(value) || !Number.isSafeInteger(Number(value))) {
    throw new Error('Enter a decimal or hexadecimal (0x…) offset.');
  }
  return Number(value);
}

function findBytes(offset, query, mode) {
  return perform('Searching file bytes…', async () => {
    const result = await call('search-bytes', { offset, query, mode });
    activeSearch = { query, mode };
    nextSearch = result.next;
    byId('find-start').value = address(offset);
    byId('find-more').hidden = nextSearch === null;
    const found = result.offsets.length + (result.offsets.length === 1 ? ' match' : ' matches');
    byId('find-info').textContent = found + ' · ' + address(result.from) + ' to ' + address(result.end) + ' (exclusive)';
    byId('find-results').replaceChildren(...result.offsets.map(offset => {
      const li = node('li');
      li.append(actionButton(address(offset), () => jumpTo(offset, result.length)));
      return li;
    }));
  });
}

function open(file) {
  if (file) perform('Inspecting file…', async () => {
    show(await call('open', { file }));
    byId('filename').scrollIntoView({ block: 'center' });
  });
}

const input = byId('file');
byId('choose').addEventListener('click', () => input.click());
input.addEventListener('change', () => {
  open(input.files[0]);
  input.value = '';
});
const candidateInput = byId('candidate');
byId('compare').addEventListener('click', () => {
  if (!busy) candidateInput.click();
});
candidateInput.addEventListener('change', () => {
  const file = candidateInput.files[0];
  candidateInput.value = '';
  const nested = byId('nested-compare').checked;
  if (file) perform('Comparing archives…', async () => showComparison(await call('compare', { file, nested })));
});
byId('comparison-scope').addEventListener('change', () => { comparisonPage = 0; renderComparison(); });
byId('comparison-search').addEventListener('input', () => { comparisonPage = 0; renderComparison(); });
byId('comparison-prev').addEventListener('click', () => { comparisonPage--; renderComparison(); });
byId('comparison-next').addEventListener('click', () => { comparisonPage++; renderComparison(); });

const drop = byId('drop');
for (const event of ['dragenter', 'dragover']) drop.addEventListener(event, e => {
  e.preventDefault();
  drop.classList.add('is-over');
});
drop.addEventListener('dragleave', e => {
  if (!(e.relatedTarget instanceof Node) || !drop.contains(e.relatedTarget)) drop.classList.remove('is-over');
});
drop.addEventListener('drop', e => {
  e.preventDefault();
  drop.classList.remove('is-over');
  open(e.dataTransfer.files[0]);
});
for (const event of ['dragover', 'drop']) window.addEventListener(event, e => e.preventDefault());

byId('parent').addEventListener('click', () =>
  perform('Opening parent…', async () => show(await call('parent')))
);
byId('search').addEventListener('input', () => { page = 0; renderRows(); });
byId('prev').addEventListener('click', () => { page--; renderRows(); });
byId('next').addEventListener('click', () => { page++; renderRows(); });

function activateTab(name, focus) {
  setTab(name, focus);
  if (name === 'hex' && !byId('hexview').textContent) perform('Reading bytes…', () => showHex(0));
}

for (const name of Object.keys(tabs)) {
  const button = byId('tab-' + name);
  button.addEventListener('click', () => activateTab(name, false));
  button.addEventListener('keydown', event => {
    const visible = Object.keys(tabs).filter(key => !byId('tab-' + key).hidden);
    const index = visible.indexOf(name);
    const target = {
      ArrowLeft: (index + visible.length - 1) % visible.length,
      ArrowRight: (index + 1) % visible.length, Home: 0, End: visible.length - 1
    }[event.key];
    if (target === undefined) return;
    event.preventDefault();
    activateTab(visible[target], true);
  });
}

byId('jump').addEventListener('submit', event => {
  event.preventDefault();
  try {
    const offset = parseOffset(byId('offset').value);
    perform('Reading bytes…', () => showHex(offset, null));
  } catch (error) {
    status(error.message, true);
  }
});

byId('run-checks').addEventListener('click', () => perform('Checking ZIP layout…', async () => {
  current.report.zipChecks = await call('checks');
  checkPage = 0;
  updateChecks();
}));
byId('verify-zip').addEventListener('click', () => perform('Verifying ZIP payloads…', async () => {
  current.report.zipChecks = await call('verify-zip');
  checkPage = 0;
  updateChecks();
}));
byId('check-prev').addEventListener('click', () => { checkPage--; updateChecks(); });
byId('check-next').addEventListener('click', () => { checkPage++; updateChecks(); });

byId('find-form').addEventListener('submit', event => {
  event.preventDefault();
  try {
    findBytes(parseOffset(byId('find-start').value), byId('find-query').value, byId('find-mode').value);
  } catch (error) {
    status(error.message, true);
  }
});
byId('find-mode').addEventListener('change', () => {
  byId('find-query').placeholder = byId('find-mode').value === 'hex' ? '55 6E ?? 74' : 'UnityFS';
});
byId('find-more').addEventListener('click', () => {
  if (nextSearch !== null) findBytes(nextSearch, activeSearch.query, activeSearch.mode);
});

byId('hex-prev').addEventListener('click', () =>
  perform('Reading bytes…', () => showHex(Math.max(0, hexPage.offset - 256)))
);
byId('hex-next').addEventListener('click', () =>
  perform('Reading bytes…', () => showHex(hexPage.offset + hexPage.bytes.length))
);
byId('endian').addEventListener('change', renderInspector);

byId('scan').addEventListener('click', () => perform('Scanning strings…', async () => {
  const result = await call('strings');
  current.report.strings = result;
  byId('string-info').textContent = digits.format(result.rows.length) + ' strings in ' +
    bytes(result.scannedBytes) + (result.truncated ? ' · Result limit reached' : '');
  byId('string-rows').replaceChildren(...result.rows.map(({ offset, encoding, text }) => {
    const tr = node('tr');
    const at = node('td');
    at.append(actionButton(address(offset), () =>
      perform('Reading bytes…', async () => {
        await showHex(offset, null);
        setTab('hex', true);
      })
    ));
    tr.append(at, node('td', encoding), node('td', text));
    return tr;
  }));
}));

byId('hash').addEventListener('click', () => perform('Computing SHA-256…', async () => {
  const digest = await call('sha256');
  current.report.sha256 = digest;
  byId('digest').textContent = digest;
}));

function downloadBlob(blob, name, suffix) {
  const url = URL.createObjectURL(blob);
  const link = node('a');
  link.href = url;
  const base = name.split(/[\\/]/).at(-1).replace(/[^\p{L}\p{N}. _-]/gu, '_').slice(0, 110) || 'file';
  link.download = base + suffix;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

function downloadJson(payload, name, suffix) {
  downloadBlob(new Blob([JSON.stringify(payload, null, 2) + '\n'], { type: 'application/json' }), name, suffix);
}

byId('download-member').addEventListener('click', () => perform('Preparing download…', async () => {
  downloadBlob(await call('download'), current.report.name, '');
}));

byId('export').addEventListener('click', () => {
  downloadJson({ ...current.report, path: current.path }, current.report.name, '.gameautopsy.json');
});
byId('export-comparison').addEventListener('click', () => {
  downloadJson(comparison, comparison.candidate, '.gameautopsy-comparison.json');
});

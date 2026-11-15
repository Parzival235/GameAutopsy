import { interpretBytes } from './hex.mjs';

const byId = id => document.getElementById(id);
const pageSize = 80;
const digits = new Intl.NumberFormat('en-US');
const mobile = matchMedia('(max-width: 760px)');
const setOrientation = () => document.querySelector('.tabs').setAttribute('aria-orientation', mobile.matches ? 'horizontal' : 'vertical');
mobile.addEventListener('change', setOrientation);
setOrientation();
const tabs = { structure: 'structure', 'unity-fields': 'unity-fields', 'unity-diff': 'unity-diff', inventory: 'inventory', binary: 'binary', hex: 'hex', compare: 'comparison', 'apk-set': 'apk-set', checks: 'checks', find: 'find', strings: 'strings' };
const worker = new Worker('./worker.mjs?v=0.12.0', { type: 'module' });
let current;
let page = 0;
let comparison;
let comparisonPage = 0;
let inventory;
let apkSet;
let apkNotesPage = 0;
let inventoryPage = 0;
let binaryDiff;
let unityFields;
let unityFieldsPage = 0;
let unityDiff;
let unityDiffPage = 0;
let binaryPage = 0;
let hexPage;
let highlighted;
let checkPage = 0;
let nextSearch;
let activeSearch;
let requestId = 0;
let busy = false;
let workerError;
let hashRequest;
const pending = new Map();

const hex = (number, width = 0) => number.toString(16).toUpperCase().padStart(width, '0');
const address = number => number == null ? '—' : '0x' + hex(number);
const bytes = number => number == null ? '—' : digits.format(number) + ' B';

worker.addEventListener('message', ({ data: { id, data, error, canceled, progress } }) => {
  const callback = pending.get(id);
  if (!callback) return;
  if (progress) {
    activityProgress(progress);
    return;
  }
  pending.delete(id);
  if (error) callback.reject(canceled ? new DOMException(error, 'AbortError') : new Error(error));
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
  if (action === 'sha256') {
    hashRequest = id;
    byId('hash-cancel').hidden = false;
    byId('hash-cancel').disabled = false;
  }
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
  const activity = byId('activity');
  const label = byId('status');
  if (label.textContent !== text) label.textContent = text;
  activity.hidden = !text;
  activity.dataset.state = error ? 'error' : busy ? 'busy' : 'done';
  label.classList.toggle('error', error);
}

function activityProgress({ stage, done, total, unit, detail }) {
  status(stage);
  const bar = byId('activity-progress');
  const measured = Number.isFinite(total) && total > 0 && Number.isFinite(done);
  bar.hidden = false;
  if (measured) {
    bar.max = total;
    bar.value = done;
    bar.setAttribute('aria-valuetext', digits.format(done) + ' of ' + digits.format(total) + ' ' + unit);
  } else {
    bar.removeAttribute('value');
    bar.removeAttribute('aria-valuetext');
  }
  byId('activity-count').textContent = measured ? Math.floor(100 * done / total) + '%' : '';
  const measuredText = measured ? digits.format(done) + ' / ' + digits.format(total) + ' ' + unit : '';
  const details = [measuredText, detail].filter(Boolean).join(' · ');
  byId('activity-detail').textContent = details;
  byId('activity-detail').hidden = !details;
}

async function perform(label, work) {
  if (busy) return;
  busy = true;
  byId('workspace').setAttribute('aria-busy', 'true');
  byId('choose').disabled = true;
  byId('export-full').disabled = true;
  activityProgress({ stage: label });
  let message;
  let error;
  try {
    message = await work();
  } catch (failure) {
    if (failure.name === 'AbortError') message = failure.message;
    else error = failure.message;
  } finally {
    busy = false;
    hashRequest = undefined;
    byId('hash-cancel').hidden = true;
    byId('choose').disabled = false;
    byId('export-full').disabled = false;
    byId('workspace').setAttribute('aria-busy', 'false');
    byId('activity-progress').hidden = true;
    byId('activity-count').textContent = '';
    byId('activity-detail').hidden = true;
    status(error ?? (typeof message === 'string' ? message : 'Analysis ready'), Boolean(error));
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
      perform('Opening entry…', async () => show(await call('member', { index })))
    ));
    if (entry.offset != null && entry.offset < current.report.size) {
      actions.append(actionButton('Hex', () =>
        jumpTo(entry.offset, entry.packed == null ? entry.size : Math.min(entry.directoryOffset - entry.offset, 30))
      ));
    }
    if (entry.kind === 'Unity object' && entry.offset != null && entry.size &&
        current.report.unitySerialized?.typeTrees?.[entry.typeIndex]) {
      actions.append(actionButton('Fields', () => showUnityFields(index)));
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
  const breadcrumbs = [];
  for (const [index, name] of path.entries()) {
    if (index) {
      const separator = node('span', ' › ');
      separator.setAttribute('aria-hidden', 'true');
      breadcrumbs.push(separator);
    }
    if (index === path.length - 1) {
      const active = node('span', path.length === 1 ? 'Root file' : 'Current file');
      active.setAttribute('aria-current', 'location');
      breadcrumbs.push(active);
    } else {
      const button = node('button', name);
      button.addEventListener('click', () => perform('Opening ancestor…', async () =>
        show(await call('ancestor', { index }))));
      breadcrumbs.push(button);
    }
  }
  byId('path').replaceChildren(...breadcrumbs);
  document.body.classList.add('has-file');
  byId('export-feedback').hidden = true;
  byId('filename').textContent = report.name;
  byId('parent').hidden = path.length === 1;
  byId('compare').hidden = report.format !== 'ZIP';
  byId('tab-inventory').hidden = !data.inventoryAvailable;
  clearByteResult();
  unityFields = undefined;
  byId('tab-unity-fields').hidden = true;
  byId('tab-unity-diff').hidden = !report.unitySerialized;
  byId('unity-diff-candidate-name').textContent = '';
  byId('unity-diff-member-label').hidden = true;
  byId('unity-diff-member').replaceChildren();
  byId('unity-diff-id').value = '';
  byId('unity-diff-run').disabled = true;
  byId('unity-diff-output').hidden = true;
  unityDiff = undefined;
  byId('nested-option').hidden = report.format !== 'ZIP';
  byId('verify-content-option').hidden = report.format !== 'ZIP';
  byId('tab-apk-set').hidden = !data.apkSetAvailable;
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
  byId('string-encoding').value = report.strings?.mode && report.strings.mode !== 'sample' ? report.strings.mode : 'utf8';
  byId('string-min').value = report.strings?.minLength ?? 6;
  byId('string-offset').value = address(report.strings?.from ?? 0);
  renderStrings(report.strings);
  byId('digest').textContent = report.sha256 ?? '';
  page = 0;
  setTab('structure');
  renderRows();
  byId('workspace').hidden = false;
  byId('file-prompt').textContent = 'Open another file';
}

function renderUnityFields() {
  if (!unityFields) return;
  const query = byId('unity-fields-search').value.trim().toLowerCase();
  const rows = unityFields.rows;
  const paths = [];
  const fieldPath = row => paths[row.id] ??= row.parent == null || rows[row.parent]?.parent == null
    ? row.name : fieldPath(rows[row.parent]) + (row.name.startsWith('[') ? '' : '.') + row.name;
  const matches = rows.filter(row => !query || [fieldPath(row), row.type, row.value, row.reference?.pathId, row.reference?.externalPath]
    .some(value => value != null && String(value).toLowerCase().includes(query)));
  unityFieldsPage = outputPage('unity-fields', unityFieldsPage, matches.length);
  const body = byId('unity-fields-rows');
  if (!matches.length) {
    emptyTable(body, 6, 'No matching fields.');
    return;
  }
  body.replaceChildren(...matches.slice(unityFieldsPage * pageSize, (unityFieldsPage + 1) * pageSize).map(row => {
    const tr = node('tr');
    const value = row.opaque ? 'Raw bytes' : row.reference ?
      (row.reference.pathId === '0' ? 'Null reference' : 'Path ID ' + row.reference.pathId +
        (row.reference.externalPath ? ' · ' + row.reference.externalPath : ' · File ID ' + row.reference.fileId)) :
      row.value == null && row.itemCount != null ? row.itemCount + ' items' :
      row.value === '' && !row.preview ? '""' : String(row.value ?? '—') + (row.preview ? '…' : '');
    for (const text of [fieldPath(row), row.type, value, address(row.offset), bytes(row.size)]) tr.append(node('td', text));
    const actions = node('td');
    if (row.size > 0) actions.append(actionButton('Hex', () => jumpTo(row.offset, row.size)));
    const target = row.reference?.target;
    if (target?.fields) actions.append(actionButton('Follow object', () => showUnityFields(target.index)));
    else if (target?.offset != null && target.size > 0) {
      actions.append(actionButton('Target hex', () => jumpTo(target.offset, target.size)));
    }
    tr.append(actions);
    return tr;
  }));
}

function showUnityFields(index) {
  return perform('Decoding Unity fields…', async () => {
    const result = await call('unity-fields', { index });
    unityFields = result;
    unityFieldsPage = 0;
    byId('unity-fields-search').value = '';
    byId('unity-fields-object').textContent = result.className +
      (result.name ? ' · ' + result.name : '') + ' · Path ID ' + result.pathId;
    byId('unity-fields-coverage').textContent = (result.status === 'partial' ? 'Partial · ' : '') +
      digits.format(result.rows.length) + ' field rows · ' + bytes(result.bytesAccountedFor) +
      ' of ' + bytes(result.objectSize) + ' accounted for';
    byId('unity-fields-warnings').replaceChildren(...result.warnings.map(warning => node('li', warning)));
    byId('unity-fields-warnings').hidden = !result.warnings.length;
    byId('unity-textasset').hidden = !result.textAsset;
    byId('tab-unity-fields').hidden = false;
    renderUnityFields();
    setTab('unity-fields', true);
  });
}

byId('unity-fields-back').addEventListener('click', () => setTab('structure', true));
byId('unity-fields-search').addEventListener('input', () => { unityFieldsPage = 0; renderUnityFields(); });
byId('unity-fields-prev').addEventListener('click', () => { unityFieldsPage--; renderUnityFields(); });
byId('unity-fields-next').addEventListener('click', () => { unityFieldsPage++; renderUnityFields(); });
byId('unity-fields-export').addEventListener('click', () => {
  if (unityFields) downloadJson(unityFields, unityFields.className + '-' + unityFields.pathId, '.gameautopsy-unity-fields.json');
});
byId('unity-textasset').addEventListener('click', () => perform('Preparing TextAsset download…', async () => {
  if (!unityFields?.textAsset) return;
  const data = await call('unity-textasset', { index: unityFields.objectIndex });
  downloadBlob(data, unityFields.name || 'TextAsset-' + unityFields.pathId, '.bin');
}));

const unityDiffLabels = {
  added: 'Added', removed: 'Removed', classChanged: 'Class changed', fieldsChanged: 'Fields changed',
  fieldsEqual: 'Decoded fields match', bytesChanged: 'Bytes changed', metadataChanged: 'Type metadata changed',
  moved: 'Moved · equal bytes', byteEqual: 'Equal bytes', unknown: 'Unresolved'
};
const unityDiffReasons = {
  duplicatePathId: 'Duplicate Path ID', incompleteObjectTable: 'Incomplete object table',
  pathNotIndexed: 'Path ID was not indexed', unknownClass: 'Unresolved class', invalidPayloadRange: 'Unreadable payload',
  objectSizeLimit: 'Object exceeds 8 MiB', comparisonBudget: 'Comparison limit reached',
  missingEmbeddedTypeTree: 'A supported embedded TypeTree is missing',
  fieldDecodeFailed: 'Could not decode fields', fieldByteBudget: 'Field read limit reached'
};
const unityFieldKinds = {
  added: 'Added', removed: 'Removed', layoutChanged: 'Type or length changed',
  referenceChanged: 'Reference changed', dataChanged: 'Data changed', valueChanged: 'Value changed'
};

function renderUnityDiff() {
  const query = byId('unity-diff-query').value.trim().toLowerCase();
  const rows = unityDiff.rows.filter(row => [row.pathId, row.before?.className, row.after?.className,
    unityDiffLabels[row.status], unityDiffReasons[row.reason]]
    .some(value => value?.toLowerCase().includes(query)));
  unityDiffPage = outputPage('unity-diff', unityDiffPage, rows.length);
  const body = byId('unity-diff-rows');
  if (!rows.length) {
    emptyTable(body, 6, query ? 'No matching results.' : 'No changes or unresolved objects to display.');
    return;
  }
  body.replaceChildren(...rows.slice(unityDiffPage * pageSize, (unityDiffPage + 1) * pageSize).map(row => {
    const tr = node('tr');
    const types = row.before && row.after && row.before.classId !== row.after.classId ?
      row.before.className + ' → ' + row.after.className : row.before?.className ?? row.after?.className ?? '—';
    for (const value of [row.pathId, types, unityDiffLabels[row.status], address(row.before?.offset), address(row.after?.offset)]) {
      tr.append(node('td', value));
    }
    const evidence = node('td');
    if (row.fieldDiff?.changes) {
      evidence.append(actionButton(row.fieldDiff.changes + ' field changes', () => renderUnityEvidence(row)));
    } else if (row.reason) evidence.textContent = unityDiffReasons[row.reason];
    else if (row.bytes?.firstDifference != null) evidence.textContent = 'First differing byte at object +' + address(row.bytes.firstDifference);
    else if (row.fieldDiff && !row.fieldDiff.complete) evidence.textContent = 'Partial field coverage';
    tr.append(evidence);
    return tr;
  }));
}

function renderUnityEvidence(row) {
  const diff = row.fieldDiff;
  const section = byId('unity-diff-evidence');
  const title = byId('unity-diff-evidence-title');
  title.textContent = 'Path ID ' + row.pathId + ' · Field changes';
  const notes = [
    diff.complete ? 'Both field trees read in full.' : 'Partial field coverage.',
    diff.unknownFields ? diff.unknownFields + ' fields unresolved.' : '',
    diff.omitted ? diff.omitted + ' additional changes omitted.' : '',
    ...diff.warnings.before.map(note => 'Baseline: ' + note),
    ...diff.warnings.after.map(note => 'Candidate: ' + note)
  ];
  byId('unity-diff-evidence-note').textContent = notes.filter(Boolean).join(' ');
  const body = byId('unity-diff-field-rows');
  if (!diff.fields.length) emptyTable(body, 4, 'The field evidence limit was reached.');
  else body.replaceChildren(...diff.fields.map(field => {
    const tr = node('tr');
    const label = field.path.join('.').replaceAll('.[', '[') || '(object root)';
    tr.append(node('td', label + (field.occurrence ? ' [occurrence ' + (field.occurrence + 1) + ']' : '')),
      node('td', unityFieldKinds[field.kind]));
    for (const side of ['before', 'after']) {
      const value = field[side];
      const td = node('td');
      if (!value) td.textContent = '—';
      else {
        const text = value.reference ? ((value.reference.path ?? 'File ID ' + value.reference.fileId) + ' · Path ID ' + value.reference.pathId) :
          value.value != null ? String(value.value) + (value.preview ? '…' : '') :
          value.itemCount != null ? value.itemCount + ' items' : value.type;
        td.append(node('div', text || '""'), node('small', address(value.offset) + ' · ' + bytes(value.size)));
        if (side === 'before' && value.size > 0) td.append(' ', actionButton('Hex', () => jumpTo(value.offset, value.size)));
      }
      tr.append(td);
    }
    return tr;
  }));
  section.hidden = false;
  title.scrollIntoView({ block: 'nearest' });
}

const unityFile = byId('unity-diff-file');
byId('unity-diff-choose').addEventListener('click', () => { if (!busy) unityFile.click(); });
unityFile.addEventListener('change', () => {
  const file = unityFile.files[0];
  unityFile.value = '';
  if (!file) return;
  perform('Opening Unity candidate…', async () => {
    const result = await call('unity-diff-candidate', { file });
    byId('unity-diff-candidate-name').textContent = result.name;
    byId('unity-diff-member-label').hidden = !result.members.length;
    byId('unity-diff-member').replaceChildren(...result.members.map(member => {
      const option = node('option', member.name + ' (' + bytes(member.size) + ')');
      option.value = member.index;
      return option;
    }));
    byId('unity-diff-run').disabled = false;
    byId('unity-diff-output').hidden = true;
  });
});
byId('unity-diff-form').addEventListener('submit', event => {
  event.preventDefault();
  perform('Comparing Unity objects…', async () => {
    const result = await call('unity-diff', { index: Number(byId('unity-diff-member').value),
      pathId: byId('unity-diff-id').value.trim() });
    unityDiff = result;
    unityDiffPage = 0;
    byId('unity-diff-evidence').hidden = true;
    byId('unity-diff-query').value = '';
    const c = result.coverage;
    byId('unity-diff-coverage').textContent =
      result.baseline + ' → ' + (result.candidateContainer ? result.candidateContainer + ' › ' : '') + result.candidate +
      ' · Object tables ' + c.beforeIndexed + '/' + c.beforeDeclared + ' and ' + c.afterIndexed + '/' + c.afterDeclared +
      ' · ' + c.pairs + ' payload pairs checked · ' + c.fieldPairs + ' field comparisons (' +
      c.partialFieldPairs + ' partial) · ' + result.counts.unknown + ' unresolved' +
      (c.omittedRows ? ' · ' + c.omittedRows + ' object rows omitted' : '') +
      (c.omittedFields ? ' · ' + c.omittedFields + ' field changes omitted' : '');
    definitions(byId('unity-diff-counts'), Object.fromEntries(Object.entries(result.counts)
      .filter(([, value]) => value > 0).map(([key, value]) => [unityDiffLabels[key], digits.format(value)])));
    renderUnityDiff();
    byId('unity-diff-output').hidden = false;
  });
});
byId('unity-diff-query').addEventListener('input', () => { unityDiffPage = 0; renderUnityDiff(); });
byId('unity-diff-prev').addEventListener('click', () => { unityDiffPage--; renderUnityDiff(); });
byId('unity-diff-next').addEventListener('click', () => { unityDiffPage++; renderUnityDiff(); });
byId('unity-diff-export').addEventListener('click', () => {
  if (unityDiff) downloadJson(unityDiff, unityDiff.candidate, '.gameautopsy-unity-diff.json');
});

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
  ambiguous: 'Duplicate path', encrypted: 'Encrypted entry', payloadChanged: 'Payload bytes differ'
};

function compareEvidence(payload) {
  if (!payload) return '—';
  if (payload.status === 'equal') return 'Byte-for-byte match';
  if (payload.status === 'failed') return 'Could not verify · ' + payload.reason;
  const first = 'First difference at ' + address(payload.firstDifference);
  return first + (payload.sameSizeAndCrc32 ? ' · Same size and CRC32' : '');
}

function renderComparison() {
  const query = byId('comparison-search').value.trim().toLowerCase();
  const index = Number(byId('comparison-scope').value);
  const scope = index ? comparison.nested.groups[index - 1] : comparison;
  definitions(byId('comparison-stats'), Object.fromEntries(
    Object.entries(scope.counts).map(([key, count]) => [comparisonLabels[key], digits.format(count)])
  ));
  const coverage = scope.payloadCoverage?.counts;
  byId('comparison-match-option').hidden = !coverage;
  const showMatches = byId('comparison-show-matches').checked;
  const visible = scope.rows.filter(row => row.status !== 'matched' || row.payload?.status === 'failed' || showMatches);
  const matches = visible.filter(row => [row.name, comparisonLabels[row.status], compareEvidence(row.payload)]
    .some(value => value.toLowerCase().includes(query)));
  const skipped = coverage ? coverage.shared - coverage.attempted : 0;
  byId('comparison-note').textContent = coverage
    ? coverage.attempted + ' of ' + coverage.shared + ' shared paths checked · ' + coverage.equal + ' equal byte for byte · ' +
      coverage.different + ' different · ' + coverage.failed + ' could not verify · ' + skipped + ' skipped' +
      (skipped ? ' (' + coverage.ambiguous + ' duplicate, ' + coverage.unavailable + ' unsupported or encrypted, ' +
        (coverage.sizeLimit + coverage.budgetLimit) + ' over limits).' : '.')
    : 'Comparison uses ZIP directory metadata. Matching sizes and CRC32 do not prove byte equality.';
  const last = Math.max(0, Math.ceil(matches.length / pageSize) - 1);
  comparisonPage = Math.min(comparisonPage, last);
  const items = matches.slice(comparisonPage * pageSize, (comparisonPage + 1) * pageSize);
  const rows = items.map(entry => {
    const tr = node('tr');
    const packed = group => group.length > 1 ? group.length + ' entries' : bytes(group[0]?.packed);
    const delta = entry.packedDelta > 0 ? '+' + bytes(entry.packedDelta) : bytes(entry.packedDelta);
    for (const value of [entry.name, comparisonLabels[entry.status], compareEvidence(entry.payload), packed(entry.before), packed(entry.after), delta]) {
      tr.append(node('td', value));
    }
    const actions = node('td');
    if (entry.canDiff) actions.append(actionButton('Diff bytes', () => compareEntry(index, entry.name)));
    tr.append(actions);
    return tr;
  });
  if (!rows.length) {
    const tr = node('tr');
    const cell = node('td', visible.length ? 'No matching results.' : 'No differences to display.');
    cell.colSpan = 7;
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
  if (binaryDiff?.source) clearByteResult();
  comparison = result;
  comparison.path = current.path;
  comparisonPage = 0;
  byId('comparison-search').value = '';
  byId('comparison-entry-path').value = '';
  byId('comparison-show-matches').checked = false;
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
  byId('comparison-notices').hidden = !nested;
  byId('comparison-notices').open = false;
  if (nested) {
    byId('comparison-notices-title').textContent = groups.length + ' nested pairs compared · ' +
      (nested.byteEqualArchives ? nested.byteEqualArchives + ' byte-for-byte archive matches · ' : '') +
      nested.matchingArchives + ' metadata matches not reopened · ' + nested.skipped + ' skipped';
    const notices = nested.notices.map(item => node('li', item.path.join(' › ') + ' — ' + item.reason));
    if (nested.skipped > notices.length) notices.push(node('li', 'Additional skipped paths are counted in the total.'));
    if (!notices.length) notices.push(node('li', 'No additional skipped archive paths.'));
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
    const result = await call('open', { file });
    inventory = undefined;
    apkSet = undefined;
    byId('apk-set-abi').value = '';
    byId('apk-set-filter').value = '';
    renderApkSet();
    renderInventory();
    show(result);
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
  const verifyPayloads = byId('verify-content').checked;
  if (file) perform('Comparing archives…', async () => showComparison(await call('compare', { file, nested, verifyPayloads })));
});
byId('comparison-scope').addEventListener('change', () => { comparisonPage = 0; renderComparison(); });
byId('comparison-entry-form').addEventListener('submit', event => {
  event.preventDefault();
  compareEntry(Number(byId('comparison-scope').value), byId('comparison-entry-path').value);
});
byId('comparison-search').addEventListener('input', () => { comparisonPage = 0; renderComparison(); });
byId('comparison-show-matches').addEventListener('change', () => { comparisonPage = 0; renderComparison(); });
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
      ArrowUp: mobile.matches ? undefined : (index + visible.length - 1) % visible.length,
      ArrowDown: mobile.matches ? undefined : (index + 1) % visible.length,
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

function renderStrings(result) {
  byId('string-next').hidden = !result?.next;
  if (!result) {
    byId('string-info').textContent = 'Scans up to 4 MiB or 500 matches per pass.';
    byId('string-rows').replaceChildren();
    return;
  }
  byId('string-info').textContent = digits.format(result.rows.length) + ' strings · ' +
    address(result.from) + ' to ' + address(result.end) + ' (exclusive)' +
    (result.limited || result.truncated ? ' · Result limit reached' : '');
  byId('string-rows').replaceChildren(...result.rows.map(row => {
    const { offset, encoding, text, byteLength, length, continuation, continues } = row;
    const tr = node('tr');
    const at = node('td');
    at.append(actionButton(address(offset), () => jumpTo(offset, byteLength)));
    const preview = (continuation ? '…' : '') + text + (continues || length > 240 ? '…' : '');
    tr.append(at, node('td', encoding), node('td', preview));
    return tr;
  }));
}

async function scanText(options) {
  current.report.strings = await call('strings', { stringOptions: options });
  byId('string-offset').value = address(options.offset);
  renderStrings(current.report.strings);
}

byId('string-form').addEventListener('submit', event => {
  event.preventDefault();
  perform('Scanning strings…', () => scanText({
    offset: parseOffset(byId('string-offset').value),
    mode: byId('string-encoding').value,
    minLength: byId('string-min').valueAsNumber
  }));
});
byId('string-next').addEventListener('click', () => {
  const { next, mode, minLength } = current.report.strings;
  if (next) perform('Continuing string scan…', () => {
    byId('string-encoding').value = mode;
    byId('string-min').value = minLength;
    return scanText({ ...next, mode, minLength });
  });
});
for (const id of ['string-encoding', 'string-min', 'string-offset']) {
  byId(id).addEventListener('input', () => { byId('string-next').hidden = true; });
}

byId('hash-cancel').addEventListener('click', () => {
  if (hashRequest == null) return;
  byId('hash-cancel').disabled = true;
  worker.postMessage({ cancelHash: hashRequest });
});

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
byId('export-full').addEventListener('click', () => perform('Preparing the full report…', async () => {
  const result = await call('full-report');
  for (const [name, value] of Object.entries(result.updates)) {
    if (value != null) current.report[name] = value;
  }
  renderStrings(current.report.strings);
  byId('digest').textContent = current.report.sha256 ?? '';
  updateChecks();
  if (result.inventory) showInventory(result.inventory);
  if (result.apkSet && !apkSet) showApkSet(result.apkSet);
  downloadBlob(result.output, result.name, '.gameautopsy-full.json');
  const feedback = byId('export-feedback');
  feedback.textContent = 'Full JSON prepared · ' + result.files + ' file reports · ' + result.operations + ' recorded operations' +
    (result.warnings ? ' · ' + result.warnings + ' incomplete checks' : '') +
    (result.omitted ? ' · ' + result.omitted + ' history entries beyond the report limit' : '');
  feedback.hidden = false;
  return 'Full report prepared';
}));

byId('export-comparison').addEventListener('click', () => {
  downloadJson(comparison, comparison.candidate, '.gameautopsy-comparison.json');
});

function outputPage(name, index, length) {
  const count = Math.max(1, Math.ceil(length / pageSize));
  const page = Math.max(0, Math.min(index, count - 1));
  byId(name + '-pages').hidden = count <= 1;
  byId(name + '-page').textContent = (page + 1) + ' / ' + count;
  byId(name + '-prev').disabled = page === 0;
  byId(name + '-next').disabled = page >= count - 1;
  return page;
}

function renderInventory() {
  byId('inventory-output').hidden = !inventory;
  byId('inventory-export').hidden = !inventory;
  byId('inventory-coverage').hidden = !inventory?.notices.length;
  if (!inventory) {
    byId('inventory-summary').textContent = 'Index supported archive members from the root file.';
    byId('inventory-query').value = '';
    byId('inventory-category').value = '';
    byId('inventory-pages').hidden = true;
    byId('inventory-rows').replaceChildren();
    inventoryPage = 0;
    return;
  }
  const terms = byId('inventory-query').value.trim().toLowerCase().split(/\s+/);
  const category = byId('inventory-category').value;
  const matches = inventory.rows.filter(row => {
    if (category && row.category !== category) return false;
    const text = [...row.path, row.name, row.kind, row.category, row.detectedFormat].join(' ').toLowerCase();
    return terms.every(term => text.includes(term));
  });
  inventoryPage = outputPage('inventory', inventoryPage, matches.length);
  byId('inventory-summary').textContent = digits.format(matches.length) + ' of ' + digits.format(inventory.rows.length) +
    ' entries · ' + inventory.containers + ' containers · ' + inventory.skipped + ' coverage notes' +
    (inventory.truncated ? ' · Inventory limit reached' : '');
  byId('inventory-rows').replaceChildren(...matches.slice(inventoryPage * pageSize, (inventoryPage + 1) * pageSize).map(row => {
    const tr = node('tr');
    for (const cell of [row.name, row.path.join(' › '), row.detectedFormat ?? row.category, bytes(row.size)]) {
      tr.append(node('td', cell));
    }
    const actions = node('td');
    if (row.open) actions.append(actionButton('Open', () => perform('Opening inventory entry…', async () => {
      show(await call('inventory-open', { index: row.id }));
    })));
    else actions.textContent = 'Metadata only';
    tr.append(actions);
    return tr;
  }));
}

function showInventory(result) {
  inventory = result;
  inventoryPage = 0;
  const notices = inventory.notices.map(item => node('li', item.path.join(' › ') + ' — ' + item.reason));
  if (inventory.skipped > notices.length) notices.push(node('li', 'Additional notices are counted in the total.'));
  byId('inventory-notices').replaceChildren(...notices);
  renderInventory();
}

byId('inventory-run').addEventListener('click', () => perform('Indexing the root archive…', async () =>
  showInventory(await call('inventory'))
));
for (const [id, event] of [['inventory-query', 'input'], ['inventory-category', 'change']]) {
  byId(id).addEventListener(event, () => { inventoryPage = 0; renderInventory(); });
}
byId('inventory-prev').addEventListener('click', () => { inventoryPage--; renderInventory(); });
byId('inventory-next').addEventListener('click', () => { inventoryPage++; renderInventory(); });
byId('inventory-export').addEventListener('click', () =>
  downloadJson(inventory, inventory.root, '.gameautopsy-inventory.json')
);

const diffKinds = { changed: 'Changed', beforeOnly: 'Current file only', afterOnly: 'Comparison file only' };
async function showBytePreview(offset) {
  const result = await call('diff-preview', { offset });
  const count = Math.max(result.before.length, result.after.length);
  for (const [id, values, other] of [
    ['byte-left', result.before, result.after], ['byte-right', result.after, result.before]
  ]) {
    const out = document.createDocumentFragment();
    for (let i = 0; i < count; i += 16) {
      out.append(hex(offset + i, 8) + '  ');
      for (let j = i; j < Math.min(i + 16, count); j++) {
        const text = values[j] === undefined ? '··' : hex(values[j], 2);
        out.append(values[j] === other[j] ? text : node('mark', text), ' ');
      }
      if (i + 16 < count) out.append('\n');
    }
    byId(id).replaceChildren(count ? out : 'Empty files.');
  }
  byId('byte-offset').value = address(offset);
}

function renderBinaryRanges() {
  binaryPage = outputPage('byte', binaryPage, binaryDiff.ranges.length);
  byId('byte-rows').replaceChildren(...binaryDiff.ranges.slice(binaryPage * pageSize, (binaryPage + 1) * pageSize).map(range => {
    const tr = node('tr');
    const at = node('td');
    at.append(actionButton(address(range.offset), () => perform('Reading both files…', () => showBytePreview(range.offset))));
    tr.append(at, node('td', bytes(range.length)), node('td', diffKinds[range.kind]));
    return tr;
  }));
}

function clearByteResult() {
  binaryDiff = undefined;
  for (const id of ['byte-result', 'byte-export', 'byte-entry-tools']) byId(id).hidden = true;
}

async function showByteResult(result) {
  const { source } = result;
  const previewOffset = result.previewOffset ?? result.ranges[0]?.offset ??
    (result.end > result.start ? result.start : Math.max(0, result.start - 1));
  await showBytePreview(previewOffset);
  binaryDiff = result;
  binaryPage = 0;
  byId('byte-entry-tools').hidden = !source;
  byId('byte-left-title').textContent = source ? 'Baseline entry' : 'Current file';
  byId('byte-right-title').textContent = source ? 'Candidate entry' : 'Comparison file';
  const entry = source ? [...source.archivePath, source.entry].join(' › ') : '';
  byId('byte-entry-path').textContent = entry;
  byId('byte-entry-path').hidden = !source;
  const before = source?.baseline.archive ?? result.before;
  const after = source?.candidate.archive ?? result.after;
  byId('byte-files').textContent = before + ' (' + bytes(result.beforeSize) + ') ↔ ' +
    after + ' (' + bytes(result.afterSize) + ')';
  const coverage = '[' + address(result.start) + ', ' + address(result.end) + ') at the same offsets';
  const equality = !result.totalRanges ?
    (result.start === 0 && result.next === null ? 'Payloads identical byte for byte. ' : 'Scanned bytes match. ') : '';
  byId('byte-coverage').textContent = equality + coverage +
    (result.omittedRanges ? ' · ' + digits.format(result.omittedRanges) + ' additional ranges counted' : '');
  definitions(byId('byte-stats'), {
    Changed: bytes(result.changed), 'Current only': bytes(result.beforeOnly), 'Comparison only': bytes(result.afterOnly),
    Ranges: digits.format(result.totalRanges)
  });
  byId('byte-more').hidden = result.next === null;
  renderBinaryRanges();
  byId('byte-result').hidden = false;
  byId('byte-export').hidden = false;
}

function scanBinary(offset, file) {
  return perform('Comparing bytes…', async () => showByteResult(await call('diff-bytes', { offset, file })));
}

function compareEntry(scope, entryName) {
  return perform('Opening both entries…', async () => {
    await showByteResult(await call('diff-entry', { scope, entryName }));
    setTab('binary', true);
  });
}

byId('byte-back-comparison').addEventListener('click', () => setTab('compare', true));
for (const [id, side, prefix] of [
  ['byte-save-baseline', 'before', 'baseline-'], ['byte-save-candidate', 'after', 'candidate-']
]) {
  byId(id).addEventListener('click', () => perform('Preparing entry download…', async () => {
    const source = binaryDiff?.source;
    if (!source) return;
    const data = await call('diff-entry-download', { side });
    downloadBlob(data, prefix + (source.entry.split(/[\\/]/).at(-1) || 'entry'), '');
  }));
}
const byteInput = byId('byte-candidate');
byId('byte-choose').addEventListener('click', () => { if (!busy) byteInput.click(); });
byteInput.addEventListener('change', () => {
  const file = byteInput.files[0];
  byteInput.value = '';
  if (file) scanBinary(0, file);
});
byId('byte-form').addEventListener('submit', event => {
  event.preventDefault();
  try {
    const offset = parseOffset(byId('byte-offset').value);
    if (event.submitter?.value === 'scan') scanBinary(offset);
    else perform('Reading both files…', () => showBytePreview(offset));
  } catch (error) {
    status(error.message, true);
  }
});
byId('byte-more').addEventListener('click', () => scanBinary(binaryDiff.next));
byId('byte-prev').addEventListener('click', () => { binaryPage--; renderBinaryRanges(); });
byId('byte-next').addEventListener('click', () => { binaryPage++; renderBinaryRanges(); });
byId('byte-export').addEventListener('click', () =>
  downloadJson(binaryDiff, binaryDiff.after, '.gameautopsy-byte-diff.json')
);

function emptyTable(body, columns, label) {
  const row = node('tr');
  const cell = node('td', label);
  cell.colSpan = columns;
  row.append(cell);
  body.replaceChildren(row);
}

function renderApkSet() {
  byId('apk-set-result').hidden = !apkSet;
  byId('apk-set-export').hidden = !apkSet;
  if (!apkSet) return;
  const groupIndex = byId('apk-set-group').value;
  const group = groupIndex === '' ? null : apkSet.groups[Number(groupIndex)];
  const paths = group ? new Set(group.paths) : null;
  const query = byId('apk-set-filter').value.trim().toLowerCase();
  const items = apkSet.items.filter(item =>
    (!paths || paths.has(item.path)) && (!query || [
      item.path, item.manifest?.split, item.role, ...(item.abis ?? []), ...(item.engines ?? []),
      ...(item.native ?? []).map(lib => lib.path)
    ].join(' ').toLowerCase().includes(query))
  );
  const body = byId('apk-set-rows');
  if (!items.length) emptyTable(body, 6, 'No matching APKs.');
  else body.replaceChildren(...items.map(item => {
    const tr = node('tr');
    const file = node('td', item.path);
    if (item.error) file.append(node('p', item.error));
    if (item.native?.length) {
      const info = node('details');
      info.append(node('summary', item.nativeCount + ' native libraries'));
      const list = node('ul');
      list.append(...item.native.slice(0, 24).map(lib => node('li', lib.path)));
      if (item.nativeCount > 24) list.append(node('li', 'More entries are available in the JSON report.'));
      info.append(list);
      file.append(info);
    }
    tr.append(file, node('td', [item.manifest?.split, item.role].filter(Boolean).join(' · ') || '—'),
      node('td', item.manifest?.longVersionCode ?? '—'), node('td', item.abis?.join(', ') || '—'));
    const signer = node('td');
    const schemes = item.signing?.schemes.filter(x => !x.error) ?? [];
    if (!schemes.length) signer.textContent = 'Unavailable';
    else {
      const details = node('details');
      details.append(node('summary', schemes.map(s => s.name).join(', ')));
      for (const scheme of schemes) {
        const list = node('ul');
        for (const entry of scheme.signers) {
          list.append(node('li', (entry.sdk ? 'SDK ' + entry.sdk.min + '–' + entry.sdk.max + ' · ' : '') + entry.certificateSha256));
        }
        details.append(node('strong', scheme.name), list);
      }
      signer.append(details);
    }
    tr.append(signer);
    const actions = node('td');
    if (item.entryIndex != null) actions.append(actionButton('Open', () => perform('Opening APK…', async () =>
      show(await call('apk-set-open', { index: item.entryIndex })))));
    tr.append(actions);
    return tr;
  }));
  const findings = apkSet.findings.filter(item => !group || item.group === group.label || !item.group);
  apkNotesPage = outputPage('apk-notes', apkNotesPage, findings.length);
  const notes = byId('apk-set-findings');
  if (!findings.length) emptyTable(notes, 3, 'No findings in the inspected metadata.');
  else notes.replaceChildren(...findings.slice(apkNotesPage * pageSize, (apkNotesPage + 1) * pageSize).map(finding => {
    const row = node('tr');
    const level = node('td', finding.level);
    level.dataset.level = finding.level.toLowerCase();
    row.append(level, node('td', finding.path), node('td', finding.message));
    return row;
  }));
}

function showApkSet(result) {
  apkSet = result;
  apkNotesPage = 0;
  definitions(byId('apk-set-summary'), {
    Package: result.package ?? 'Unknown', APKs: result.inspected + ' / ' + result.declared,
    'Native ABIs': result.abis.join(', ') || 'None observed',
    'Engine libraries': [...new Set(result.nativeFiles.map(item => item.name))].join(', ') || 'None observed'
  });
  byId('apk-set-info').textContent = result.source + (result.abi ? ' · Device ABI ' + result.abi : '') +
    ' · ' + result.skipped + ' APKs unreadable or skipped' +
    (result.findingsMayBeTruncated ? ' · Findings limit reached' : '');
  const selector = byId('apk-set-group');
  const all = node('option', 'All APKs');
  all.value = '';
  selector.replaceChildren(all, ...result.groups.map((group, index) => {
    const option = node('option', group.label);
    option.value = String(index);
    return option;
  }));
  renderApkSet();
}

byId('apk-set-run').addEventListener('click', () => perform('Inspecting APK set…', async () =>
  showApkSet(await call('apk-set', { abi: byId('apk-set-abi').value }))
));
byId('apk-set-group').addEventListener('change', () => { apkNotesPage = 0; renderApkSet(); });
byId('apk-set-filter').addEventListener('input', renderApkSet);
byId('apk-notes-prev').addEventListener('click', () => { apkNotesPage--; renderApkSet(); });
byId('apk-notes-next').addEventListener('click', () => { apkNotesPage++; renderApkSet(); });
byId('apk-set-export').addEventListener('click', () => downloadJson(apkSet, apkSet.name, '.gameautopsy-apk-set.json'));

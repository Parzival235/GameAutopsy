const byId = id => document.getElementById(id);
const pageSize = 80;
const digits = new Intl.NumberFormat('vi-VN');
const tabs = ['structure', 'hex', 'strings'];
const worker = new Worker('./worker.mjs', { type: 'module' });
let current;
let page = 0;
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
  workerError = new Error('Không khởi động được bộ đọc. Mở trang bằng HTTPS hoặc localhost.');
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
  if (e.packed != null) values.push('Nén ' + bytes(e.packed), 'CRC32 ' + hex(e.crc32, 8), 'CD ' + address(e.central));
  if (e.count != null) values.push(digits.format(e.count) + ' mục');
  if (e.address != null) values.push(e.address);
  if (e.line != null) values.push('Dòng ' + e.line);
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
    if (entry.open) actions.append(actionButton('Mở', () =>
      perform('Đang mở mục trong gói…', async () => show(await call('member', { index })))
    ));
    if (entry.offset != null && entry.offset < current.report.size) {
      actions.append(actionButton('Hex', () =>
        perform('Đang đọc vùng byte…', async () => {
          await showHex(entry.offset);
          setTab('hex', true);
        })
      ));
    }
    tr.append(actions);
    return tr;
  });
  if (!rows.length) {
    const tr = node('tr');
    const cell = node('td', current.report.rows.length ? 'Không tìm thấy mục khớp.' : 'Định dạng này chưa có bảng cấu trúc.');
    cell.colSpan = 6;
    tr.append(cell);
    rows.push(tr);
  }
  byId('rows').replaceChildren(...rows);
  byId('count').textContent = digits.format(matches.length) + ' mục';
  byId('page').textContent = (page + 1) + ' / ' + (last + 1);
  byId('pages').hidden = last === 0;
  byId('prev').disabled = page === 0;
  byId('next').disabled = page === last;
}

function setTab(tab, focus = false) {
  for (const name of tabs) {
    const button = byId('tab-' + name);
    const selected = name === tab;
    button.setAttribute('aria-selected', String(selected));
    button.tabIndex = selected ? 0 : -1;
    byId(name).hidden = !selected;
    if (selected && focus) button.focus();
  }
}

function show(data) {
  current = data;
  const { path, report } = current;
  const { source, details } = report;
  byId('path').textContent = path.length > 1 ? path.slice(0, -1).join(' › ') : 'File gốc';
  byId('filename').textContent = report.name;
  byId('parent').hidden = path.length === 1;
  definitions(byId('stats'), {
    'Định dạng': report.format, 'Dung lượng': bytes(report.size),
    'Hàng cấu trúc': digits.format(report.rows.length),
    'Trạng thái': report.status === 'ok' && !report.warnings.length ? 'Đã đọc' : 'Xem giới hạn bên dưới'
  });
  definitions(byId('details'), {
    ...details,
    ...(source ? { 'Local header trong gói cha': address(source.localHeaderOffset), 'Dữ liệu trong gói cha': address(source.dataOffset) } : {})
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

async function showHex(offset) {
  const data = await call('hex', { offset });
  const lines = [];
  for (let i = 0; i < data.bytes.length; i += 16) {
    const slice = data.bytes.slice(i, i + 16);
    const values = slice.map(byte => hex(byte, 2)).join(' ').padEnd(47);
    const glyphs = slice.map(byte => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.').join('');
    lines.push(hex(data.offset + i, 8) + '  ' + values + '  ' + glyphs);
  }
  byId('offset').value = address(offset);
  byId('hexview').textContent = lines.join('\n') || 'File trống.';
}

function open(file) {
  if (file) perform('Đang phân tích file…', async () => show(await call('open', { file })));
}

const input = byId('file');
byId('choose').addEventListener('click', () => input.click());
input.addEventListener('change', () => {
  open(input.files[0]);
  input.value = '';
});
const drop = byId('drop');
for (const event of ['dragenter', 'dragover']) drop.addEventListener(event, e => {
  e.preventDefault();
  drop.classList.add('is-over');
});
drop.addEventListener('dragleave', e => {
  if (!drop.contains(e.relatedTarget)) drop.classList.remove('is-over');
});
drop.addEventListener('drop', e => {
  e.preventDefault();
  drop.classList.remove('is-over');
  open(e.dataTransfer.files[0]);
});
for (const event of ['dragover', 'drop']) window.addEventListener(event, e => e.preventDefault());

byId('parent').addEventListener('click', () =>
  perform('Đang trở về gói cha…', async () => show(await call('parent')))
);
byId('search').addEventListener('input', () => { page = 0; renderRows(); });
byId('prev').addEventListener('click', () => { page--; renderRows(); });
byId('next').addEventListener('click', () => { page++; renderRows(); });

function activateTab(name, focus) {
  setTab(name, focus);
  if (name === 'hex' && !byId('hexview').textContent) perform('Đang đọc vùng byte…', () => showHex(0));
}

for (const [index, name] of tabs.entries()) {
  const button = byId('tab-' + name);
  button.addEventListener('click', () => activateTab(name, false));
  button.addEventListener('keydown', event => {
    const target = {
      ArrowLeft: (index + tabs.length - 1) % tabs.length,
      ArrowRight: (index + 1) % tabs.length, Home: 0, End: tabs.length - 1
    }[event.key];
    if (target === undefined) return;
    event.preventDefault();
    activateTab(tabs[target], true);
  });
}

byId('jump').addEventListener('submit', event => {
  event.preventDefault();
  const raw = byId('offset').value.trim();
  if (!/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(raw) || !Number.isSafeInteger(Number(raw))) {
    status('Nhập offset hệ 10 hoặc dạng 0x… hợp lệ.', true);
    return;
  }
  perform('Đang đọc vùng byte…', () => showHex(Number(raw)));
});

byId('scan').addEventListener('click', () => perform('Đang quét chuỗi…', async () => {
  const result = await call('strings');
  current.report.strings = result;
  byId('string-info').textContent = digits.format(result.rows.length) + ' chuỗi trong ' +
    bytes(result.scannedBytes) + (result.truncated ? ' · Đã đạt giới hạn kết quả' : '');
  byId('string-rows').replaceChildren(...result.rows.map(({ offset, encoding, text }) => {
    const tr = node('tr');
    const at = node('td');
    at.append(actionButton(address(offset), () =>
      perform('Đang đọc vùng byte…', async () => {
        await showHex(offset);
        setTab('hex', true);
      })
    ));
    tr.append(at, node('td', encoding), node('td', text));
    return tr;
  }));
}));

byId('hash').addEventListener('click', () => perform('Đang tính SHA-256…', async () => {
  const digest = await call('sha256');
  current.report.sha256 = digest;
  byId('digest').textContent = digest;
}));

byId('export').addEventListener('click', () => {
  const payload = { ...current.report, path: current.path };
  const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2) + '\n'], { type: 'application/json' }));
  const link = node('a');
  link.href = url;
  link.download = (current.report.name.split(/[\\/]/).at(-1).replace(/[^\p{L}\p{N}. _-]/gu, '_').slice(0, 110) || 'file') + '.gameautopsy.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
});

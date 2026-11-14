const noIndex = 0xffffffff;
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const utf16 = new TextDecoder('utf-16le', { fatal: true, ignoreBOM: true });
const hex = n => '0x' + n.toString(16).toUpperCase().padStart(8, '0');
const cap = 20000;
const shortText = s => s.length > 240 ? s.slice(0, 240) + '…' : s;

function bounded(end, start, size) {
  if (start < 0 || size < 0 || start > end || size > end - start) throw new Error('AXML field exceeds its chunk.');
}

function stringPool(bytes, d, at, header, end) {
  if (header < 28) throw new Error('Invalid AXML string pool header.');
  const count = d.getUint32(at + 8, true);
  const styles = d.getUint32(at + 12, true);
  const isUtf8 = Boolean(d.getUint32(at + 16, true) & 0x100);
  const offsets = at + header;
  const start = at + d.getUint32(at + 20, true);
  const styleStart = d.getUint32(at + 24, true);
  const limit = styleStart ? at + styleStart : end;
  bounded(end, offsets, (count + styles) * 4);
  if (!count && start === at) return { count, isUtf8, get(index) {
    if (index === noIndex) return null;
    throw new Error('AXML string index is outside the empty pool.');
  } };
  if (start < offsets + (count + styles) * 4 || start > limit || limit > end) throw new Error('Invalid AXML string data bounds.');
  const cache = new Map();
  let cachedUnits = 0;
  function get(index) {
    if (index === noIndex) return null;
    if (index >= count) throw new Error('AXML string index is outside the pool.');
    if (cache.has(index)) return cache.get(index);
    let pos = start + d.getUint32(offsets + index * 4, true);
    const width = isUtf8 ? 1 : 2;
    const length = () => {
      bounded(limit, pos, width);
      let n = isUtf8 ? bytes[pos] : d.getUint16(pos, true);
      pos += width;
      const mask = isUtf8 ? 0x80 : 0x8000;
      if (n & mask) {
        bounded(limit, pos, width);
        n = (n & (mask - 1)) * (isUtf8 ? 256 : 65536) + (isUtf8 ? bytes[pos] : d.getUint16(pos, true));
        pos += width;
      }
      return n;
    };
    const units = length();
    const size = isUtf8 ? length() : units * 2;
    bounded(limit, pos, size + width);
    if (bytes[pos + size] !== 0 || (!isUtf8 && bytes[pos + size + 1] !== 0)) throw new Error('AXML string terminator is missing.');
    if (size > 65536 || cache.size >= cap || cachedUnits + units > 4_000_000) throw new Error('AXML string decoding reached its output limit.');
    const value = (isUtf8 ? utf8 : utf16).decode(bytes.subarray(pos, pos + size));
    if (value.length !== units) throw new Error('AXML string length does not match its prefix.');
    cache.set(index, value);
    cachedUnits += units;
    return value;
  }
  return { get, count, isUtf8 };
}

function typedValue(d, at, end, pool) {
  bounded(end, at, 8);
  if (d.getUint16(at, true) !== 8 || d.getUint8(at + 2)) throw new Error('Invalid AXML typed value.');
  const type = d.getUint8(at + 3);
  const data = d.getUint32(at + 4, true);
  let value;
  switch (type) {
    case 0: value = null; break;
    case 1: case 7: value = '@' + hex(data); break;
    case 2: case 8: value = '?' + hex(data); break;
    case 3: value = pool.get(data); break;
    case 4: {
      const number = d.getFloat32(at + 4, true);
      value = Number.isFinite(number) ? number : String(number);
      break;
    }
    case 16: value = d.getInt32(at + 4, true); break;
    case 18: value = data !== 0; break;
    default: value = hex(data);
  }
  return { type, data, value: typeof value === 'string' ? shortText(value) : value };
}

export function inspectAxml(bytes, out) {
  const d = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const labels = { 1: 'String pool', 0x100: 'Start namespace', 0x101: 'End namespace', 0x102: 'Start element', 0x103: 'End element', 0x104: 'CDATA', 0x180: 'Resource map' };
  let at = d.getUint16(2, true);
  let pool;
  let resources;
  const stack = [];
  const namespaces = [];
  const manifest = {};
  const permissions = new Set();
  const android = 'http://schemas.android.com/apk/res/android';
  const describe = (uri, name) => {
    const prefix = uri ? namespaces.findLast(binding => binding.uri === uri)?.prefix : null;
    return prefix ? prefix + ':' + name : name;
  };
  const put = (name, kind, offset, size, extra = {}) => out.rows.push({ name, kind, offset, size, ...extra });
  while (at < bytes.length) {
    if (out.rows.length >= cap) {
      out.warnings.push('AXML output reached 20,000 rows.');
      return;
    }
    bounded(bytes.length, at, 8);
    const type = d.getUint16(at, true);
    const header = d.getUint16(at + 2, true);
    const length = d.getUint32(at + 4, true);
    const end = at + length;
    const ext = at + header;
    if (header < 8 || length < header) throw new Error('Invalid AXML chunk size.');
    bounded(bytes.length, at, length);
    const node = type >= 0x100 && type <= 0x104;
    if (node && (header < 16 || !pool)) throw new Error('AXML node has a missing header or string pool.');
    const line = node ? d.getUint32(at + 8, true) : undefined;
    const u32 = where => d.getUint32(where, true);
    let name = labels[type] || hex(type);
    if (type === 1) {
      pool = stringPool(bytes, d, at, header, end);
      out.details['String pool'] = (pool.isUtf8 ? 'UTF-8' : 'UTF-16LE') + ' · ' + pool.count + ' strings';
    } else if (type === 0x180) {
      if ((length - header) % 4) throw new Error('Invalid AXML resource map.');
      resources = { start: ext, count: (length - header) / 4 };
    } else if (type === 0x100 || type === 0x101) {
      bounded(end, ext, 8);
      const uri = pool.get(u32(ext + 4));
      const prefix = pool.get(u32(ext));
      name += ' ' + shortText(prefix || uri || '(default)');
      if (type === 0x100) {
        if (namespaces.length >= 256) throw new Error('AXML namespace depth exceeds 256.');
        namespaces.push({ prefix, uri });
      }
      else {
        const last = namespaces.at(-1);
        if (!last || last.uri !== uri || last.prefix !== prefix) throw new Error('AXML namespace end does not match its start.');
        namespaces.pop();
      }
    } else if (type === 0x102 || type === 0x103) {
      bounded(end, ext, type === 0x102 ? 20 : 8);
      const uri = pool.get(u32(ext));
      const element = pool.get(u32(ext + 4));
      if (!element) throw new Error('AXML element name is missing.');
      const label = shortText(describe(uri, element));
      if (type === 0x103) {
        const top = stack.pop();
        if (!top || top.element !== element || top.uri !== uri) throw new Error('AXML closing element does not match its start.');
        name = '</' + label + '>';
      } else {
        if (stack.length >= 256) throw new Error('AXML element depth exceeds 256.');
        const attrStart = d.getUint16(ext + 8, true);
        const attrSize = d.getUint16(ext + 10, true);
        const count = d.getUint16(ext + 12, true);
        if (count && (attrStart < 20 || attrSize < 20)) throw new Error('Invalid AXML attribute layout.');
        if (count) bounded(end, ext + attrStart, count * attrSize);
        name = '<' + label + '>';
        put(name, 'AXML element', at, length, { line, depth: stack.length, count });
        const parent = stack.at(-1);
        for (let i = 0; i < count; i++) {
          if (out.rows.length >= cap) {
            out.warnings.push('AXML output reached 20,000 rows.');
            return;
          }
          const offset = ext + attrStart + i * attrSize;
          const namespace = pool.get(u32(offset));
          const index = u32(offset + 4);
          const attr = pool.get(index);
          const resource = resources && index < resources.count ? u32(resources.start + index * 4) : null;
          const raw = pool.get(u32(offset + 8));
          const typed = typedValue(d, offset + 12, offset + attrSize, pool);
          const value = raw === null ? typed.value : shortText(raw);
          const attrName = shortText(attr || (resource ? '[' + hex(resource) + ']' : '[unnamed]'));
          put(label + ' @ ' + describe(namespace, attrName), 'AXML attribute', offset, attrSize, {
            line, namespace: namespace === null ? null : shortText(namespace), resourceId: resource ? hex(resource) : null,
            value, valueType: typed.type, valueData: hex(typed.data), depth: stack.length, note: value === null ? '(null)' : String(value)
          });
          if (!uri && element === 'manifest' && !parent) {
            if (namespace === null && ['package', 'split'].includes(attr)) manifest[attr] = value;
            if (namespace === android && ['versionCode', 'versionName'].includes(attr)) manifest[attr] = value;
          }
          if (!uri && parent?.element === 'manifest' && !parent.uri && namespace === android) {
            if (element === 'uses-sdk' && ['minSdkVersion', 'targetSdkVersion', 'maxSdkVersion'].includes(attr)) manifest[attr] = typed.value ?? value;
            if (/^uses-permission(?:-sdk-(?:23|m))?$/.test(element) && attr === 'name' && typeof value === 'string') permissions.add(value);
          }
        }
        if (element === 'manifest' && !uri && !parent) out.manifest = manifest;
        stack.push({ element, uri });
        at = end;
        continue;
      }
    } else if (type === 0x104) {
      bounded(end, ext, 12);
      const value = pool.get(u32(ext));
      put('CDATA', 'AXML chunk', at, length, { line, note: shortText(value ?? '') });
      at = end;
      continue;
    }
    put(name, 'AXML chunk', at, length, { headerSize: header, ...(node ? { line } : {}) });
    at = end;
  }
  if (out.manifest) {
    manifest.permissions = [...permissions].sort();
    for (const [key, value] of Object.entries(manifest)) {
      if (key === 'permissions') out.details['Permissions declared'] = value.length;
      else out.details['Manifest ' + key] = value ?? '(null)';
    }
  }
  if (stack.length || namespaces.length) throw new Error('AXML document ended with unclosed elements or namespaces.');
}

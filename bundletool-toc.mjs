const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const maxFields = 100_000;

export function parseBundletoolToc(bytes) {
  let fieldsRead = 0;
  function fields(message) {
    let offset = 0;
    const result = [];
    const varint = () => {
      let value = 0n;
      for (let i = 0; i < 10; i++) {
        if (offset === message.length) throw new Error('Truncated TOC varint.');
        const byte = message[offset++];
        if (i === 9 && byte > 1) throw new Error('Oversized TOC varint.');
        value |= BigInt(byte & 127) << BigInt(i * 7);
        if (byte < 128) return value;
      }
      throw new Error('Oversized TOC varint.');
    };
    while (offset < message.length) {
      if (++fieldsRead > maxFields) throw new Error('TOC field limit reached.');
      const tag = varint();
      if (tag > 0xffffffffn || tag < 8n) throw new Error('Invalid TOC field tag.');
      const field = Number(tag >> 3n);
      const wire = Number(tag & 7n);
      if (wire === 0) {
        result.push({ field, wire, value: varint() });
        continue;
      }
      const size = wire === 2 ? varint() : wire === 5 ? 4n : wire === 1 ? 8n : -1n;
      if (size < 0 || size > BigInt(message.length - offset)) throw new Error('Invalid TOC field length or wire type.');
      const end = offset + Number(size);
      if (wire === 2) result.push({ field, wire, value: message.subarray(offset, end) });
      offset = end;
    }
    return result;
  }
  const messages = (nodes, id) => nodes.filter(node => node.field === id && node.wire === 2);
  const parts = (nodes, id) => messages(nodes, id).map(node => fields(node.value));
  const string = (nodes, id) => {
    const item = messages(nodes, id).at(-1);
    if (!item) return '';
    if (item.value.length > 4096) throw new Error('TOC string exceeds its size limit.');
    return utf8.decode(item.value);
  };
  const number = (nodes, id) => {
    const value = nodes.findLast(node => node.field === id && node.wire === 0)?.value ?? 0n;
    if (value > 0xffffffffn) throw new Error('TOC scalar exceeds uint32.');
    return Number(value);
  };
  function descriptions(module) {
    return parts(module, 2).map(nodes => {
      const split = parts(nodes, 3).at(-1);
      const path = string(nodes, 2);
      if (!path) throw new Error('TOC APK description is missing a path.');
      return { path, kind: split ? 'split' : messages(nodes, 4).length ? 'standalone' : 'other',
        ...(split ? { splitId: string(split, 1), master: number(split, 2) !== 0 } : {}) };
    });
  }
  const root = fields(bytes);
  const variants = parts(root, 1).map(nodes => ({
    number: number(nodes, 3),
    modules: parts(nodes, 2).map(set => {
      const metadata = parts(set, 1).at(-1) ?? [];
      return {
        name: string(metadata, 1),
        dependencies: messages(metadata, 4).map(item => string([item], 4)),
        apks: descriptions(set)
      };
    })
  }));
  if (!variants.length && !messages(root, 3).length) throw new Error('No variants or asset slices in the table of contents.');
  return { package: string(root, 4), variants, assetSlices: parts(root, 3).flatMap(descriptions).map(item => item.path) };
}

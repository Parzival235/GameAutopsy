import Decoder from './vendor/lzma/decoder.mjs';

export const maxLzmaBlock = 32 * 1024 * 1024;

// UnityFS stores five LZMA1 property bytes followed by the raw stream.
// The directory or block table supplies the decoded size.
export function decodeUnityLzma(packed, size) {
  if (!Number.isInteger(size) || size < 0 || Math.max(packed.length, size) > maxLzmaBlock) {
    throw new Error('Unity LZMA input or output exceeds the 32 MiB block limit.');
  }
  if (packed.length < 10 || packed[0] >= 225 || packed[5] !== 0) {
    throw new Error('Invalid Unity LZMA properties or range header.');
  }
  const props = packed[0];
  const lc = props % 9;
  const lp = Math.floor(props / 9) % 5;
  const pb = Math.floor(props / 45);
  const declaredDictionary = new DataView(packed.buffer, packed.byteOffset, packed.byteLength).getUint32(1, true);
  const decoder = new Decoder();
  // Matches can only refer to bytes already produced in this block.
  decoder.setDictionarySize(Math.min(declaredDictionary, size));
  if (!decoder.setLcLpPb(lc, lp, pb)) throw new Error('Unsupported Unity LZMA properties.');

  const out = new Uint8Array(size);
  let source = 5;
  let written = 0;
  const input = { readByte() {
    if (source === packed.length) throw new Error('The Unity LZMA stream is truncated.');
    return packed[source++];
  } };
  const output = { writeByte(byte) {
    if (written === size) throw new Error('Unity LZMA output exceeds the declared size.');
    out[written++] = byte;
  } };
  if (!decoder.code(input, output, size) || written !== size) {
    throw new Error('Unity LZMA output does not match the declared size or contains an invalid match.');
  }
  return out;
}

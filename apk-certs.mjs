import { bytesAt } from './formats.mjs?v=0.7.0';
import { readApkSigningBlock } from './zip-checks.mjs?v=0.7.0';

const supported = new Set(['0x7109871A', '0xF05368C0', '0x1B93AD61']);

function cursor(data) {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let at = 0;
  return {
    more: () => at < data.length,
    u32() {
      if (at + 4 > data.length) throw new Error('Truncated APK signer field.');
      const length = view.getUint32(at, true);
      at += 4;
      return length;
    },
    field() {
      const length = this.u32();
      const end = at + length;
      if (end > data.length) throw new Error('APK signer field extends past its container.');
      const bytes = data.subarray(at, end);
      at = end;
      return bytes;
    }
  };
}

async function fingerprint(bytes) {
  if (bytes.length < 4 || bytes[0] !== 0x30) throw new Error('Invalid signer certificate DER envelope.');
  let width = 2;
  let length = bytes[1];
  if (length >= 128) {
    const count = length & 127;
    width += count;
    if (!count || count > 4 || width > bytes.length || bytes[2] === 0) throw new Error('Invalid signer certificate DER length.');
    length = 0;
    for (const byte of bytes.subarray(2, width)) length = length * 256 + byte;
    if (length < 128) throw new Error('Nonminimal signer certificate DER length.');
  }
  if (width + length !== bytes.length) throw new Error('Truncated signer certificate DER data.');
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, n => n.toString(16).padStart(2, '0')).join('');
}

export async function declaredApkSigners(blob, report) {
  const block = await readApkSigningBlock(blob, Number(report.details['Central directory']));
  if (!block) return { status: 'unavailable', schemes: [] };
  const schemes = [];
  for (const pair of block.pairs) {
    if (!supported.has(pair.id)) continue;
    const scheme = { name: pair.name, signers: [] };
    schemes.push(scheme);
    try {
      if (pair.size > 4 * 1024 * 1024) throw new Error('APK signer block exceeds its size limit.');
      const envelope = cursor(await bytesAt(blob, pair.offset, pair.size));
      const list = cursor(envelope.field());
      if (envelope.more()) throw new Error('Extra bytes after APK signer list.');
      while (list.more()) {
        if (scheme.signers.length === 16) throw new Error('APK signer count exceeds its limit.');
        const signer = cursor(list.field());
        const data = cursor(signer.field());
        data.field(); // Digests precede the certificate list.
        const certificates = cursor(data.field());
        const leaf = certificates.field();
        let sdk;
        if (pair.name !== 'APK v2') {
          const min = data.u32();
          const max = data.u32();
          if (min > max || signer.u32() !== min || signer.u32() !== max) throw new Error('Inconsistent signer SDK bounds.');
          sdk = { min, max };
        }
        data.field(); // Additional attributes, including optional key history.
        // apksig emits an extra empty field in v2 signed data.
        if (pair.name === 'APK v2' && data.more() && data.field().length) throw new Error('Unexpected v2 signed-data extension.');
        signer.field(); // Signatures.
        signer.field(); // Public key.
        if (data.more() || signer.more()) throw new Error('Extra bytes after APK signer record.');
        scheme.signers.push({ certificateSha256: await fingerprint(leaf), ...(sdk ? { sdk } : {}) });
      }
      if (!scheme.signers.length) throw new Error('Empty APK signer list.');
    } catch (error) {
      scheme.error = error.message;
    }
  }
  const available = schemes.some(scheme => !scheme.error);
  return { status: available ? 'declared' : schemes.length ? 'unreadable' : 'unavailable', schemes };
}

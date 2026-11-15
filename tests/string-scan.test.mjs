import assert from 'node:assert/strict';
import test from 'node:test';
import { scanStrings } from '../string-scan.mjs';

const MiB = 1024 * 1024;

test('UTF-8 scan preserves Vietnamese, Japanese and supplementary characters at exact byte offsets', async () => {
  const text = 'Tiếng Việt 日本語 🐧';
  const prefix = Uint8Array.of(0xe0, 0x81, 0x81, 0xed, 0xa0, 0x80, 0xf4, 0x90, 0x80, 0x80, 0);
  const result = await scanStrings(new Blob([prefix, text, '\0', 'ASCII text']));
  assert.deepEqual(result.rows.map(({ offset, encoding, byteLength, text }) => ({ offset, encoding, byteLength, text })), [
    { offset: prefix.length, encoding: 'UTF-8', byteLength: Buffer.byteLength(text), text },
    { offset: prefix.length + 1 + Buffer.byteLength(text), encoding: 'ASCII', byteLength: 10, text: 'ASCII text' }
  ]);
  assert.equal(result.rows[0].length, [...text].length);
  assert.equal(result.next, null);
});

test('wide scans honor the selected byte order and odd alignment', async () => {
  const text = '日本語 và 🐧';
  for (const mode of ['utf16le', 'utf16be']) {
    const wide = Buffer.from(text, 'utf16le');
    if (mode === 'utf16be') wide.swap16();
    const invalid = mode === 'utf16le' ? Uint8Array.of(0x00, 0xdc) : Uint8Array.of(0xdc, 0x00);
    const result = await scanStrings(new Blob([Uint8Array.of(0), invalid, wide, Uint8Array.of(0)]), { offset: 1, mode });
    assert.equal(result.rows.length, 1);
    assert.equal(result.rows[0].offset, 3);
    assert.equal(result.rows[0].byteLength, wide.length);
    assert.equal(result.rows[0].text, text);
    assert.equal(result.next, null);
  }
});

test('continuation recovers a short string split across windows and later bytes after the result cap', async () => {
  const text = '日越両国の文字';
  const blob = new Blob([new Uint8Array(4 * MiB - 5), text, '\0', 'sample\0'.repeat(501)]);
  const first = await scanStrings(blob);
  assert.equal(first.rows.length, 0);
  assert.equal(first.next.offset, 4 * MiB - 5);
  const second = await scanStrings(blob, first.next);
  assert.equal(second.rows[0].text, text);
  assert.equal(second.rows.length, 500);
  assert.equal(second.limited, true);
  const third = await scanStrings(blob, second.next);
  assert.equal(third.rows.length, 2);
  assert.equal(third.next, null);
});

test('structures spanning a pass retain even a short final fragment', async () => {
  const blob = new Blob([new Uint8Array(4 * MiB - 6), 'abcdef日\0']);
  const first = await scanStrings(blob);
  assert.equal(first.rows[0].continues, true);
  assert.equal(first.next.offset, 4 * MiB);
  const second = await scanStrings(blob, first.next);
  assert.equal(second.rows[0].text, '日');
  assert.equal(second.rows[0].continuation, true);
  assert.equal(second.rows[0].continues, false);
});

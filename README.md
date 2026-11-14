# GameAutopsy

GameAutopsy is a read-only game-file inspector that runs in your browser. Open the [GitHub Pages app](https://parzival235.github.io/GameAutopsy/) and drop in a file from your device. The app reads locally, processes files in a Web Worker, and saves reports or individual entries on request.

## Inspect a file

1. Choose a file or drag it onto the page.
2. In **Structure**, search for a path, type, or offset. Use **Open** on a ZIP entry to inspect its contents, or **Hex** to highlight its range in the current file. For ZIP entries, this shortcut highlights the fixed part of the local header.
3. In **Hex**, use a decimal or hexadecimal offset, step through 256-byte pages, or interpret the bytes at the current offset as signed integers, unsigned integers, or floats in either byte order.
4. In **Find bytes**, enter UTF-8 text or a hex sequence such as `55 6E ?? 74`. Click a result to highlight the match in Hex. **Continue search** resumes at the next unchecked offset.
5. Use **Strings**, **Compute SHA-256**, or **Download JSON** on the current file. **Save open entry** downloads the bytes of an opened ZIP or UnityFS member to your device. Reports include any ZIP checks, string sample and SHA-256 you ran for the current file.

| Format | What GameAutopsy reads |
| --- | --- |
| ZIP, APK, APKS, XAPK, AAB, IPA, ZIP-based OBB | Single-disk ZIP and ZIP64 central directories. Open nested Stored or Deflate entries with CRC32 and size checks. |
| DEX | Headers, ID tables, class definition tables and map entries. DEX 041 containers can contain multiple logical files with offsets relative to the physical file. |
| ELF 32/64 | Architecture, byte order, entry address, segment permissions, sections, file offsets and 16 KiB LOAD alignment checks. |
| PE32 / PE32+ | Architecture, entry RVA, image base, sections and data directories. |
| UnityFS 6–8 | Header, block table and file directory for standard Raw, LZ4 and LZ4HC directories. Shows packed blocks and decoded file offsets. Open or save members that span Raw, LZ4 and LZ4HC blocks. |
| Android binary XML | UTF-8 and UTF-16LE pools, XML elements, attributes and typed values with exact record offsets. Manifest summary covers package, split, version, SDK levels and declared permissions. |
| Godot PCK / IL2CPP metadata | Signature and selected header fields. |
| Any file | Hex, typed values, resumable UTF-8 and wildcard byte search, entropy, string samples and optional SHA-256. |

Offsets use bytes from the start of the current file unless labeled otherwise. ZIP structure offsets point to local headers. After opening an entry, **Format and source details** gives the local header and payload offsets in the parent archive. UnityFS file entries have a separate `streamOffset` into the decoded stream, while UnityFS block offsets point into the original bundle.

## Compare two releases

Open the older ZIP-based package, then choose **Compare archive** and pick the newer package. The comparison reads both central directories and shows added or removed paths, content metadata changes, packing changes, moved offsets, duplicate paths, and encrypted entries that need separate inspection.

The packed delta is the change in an entry's compressed payload size, excluding headers and padding. The comparison uses declared uncompressed sizes and CRC32 values to classify likely content differences. Use SHA-256 on an opened entry when you need a stronger equality check. Comparison is scoped to the current ZIP level and can be downloaded as JSON.

## Check an APK or ZIP

- **Check ZIP layout** compares local headers to the central directory and reports duplicate paths, overlapping header or payload ranges, and invalid metadata. For APKs it also checks stored payload alignment at 4 bytes and stored native-library payload alignment at 16 KiB.
- **Verify entry CRC32** independently reads and verifies eligible payloads. Reports include successful, failed and skipped counts. This check processes up to 512 entries and up to 256 MiB of combined declared packed and unpacked data. Each entry remains subject to the open limit.
- APK checks identify v2, v3 and v3.1 entries in the signing block and report their offsets. Signing-block findings describe structure only. Certificate trust, cryptographic signature validity, ZIP data-descriptor contents and installation compatibility are outside these checks.
- Open a native library to see its ELF LOAD alignment separately from its APK payload alignment.

## Privacy and limits

- Files and reports stay on the device. There is no backend, telemetry, or CDN dependency. To launch the app without internet access, serve a downloaded copy on localhost.
- ZIP directories are limited to 20,000 entries or 24 MiB of directory data. ZIP comparison requires two complete directories. Encrypted, split, and unsupported compression formats remain visible as metadata when the directory can be read.
- Nested ZIPs support six levels, up to 128 MiB per opened entry and 256 MiB total for entries held open. Whole-file SHA-256 supports up to 256 MiB. The string sampler scans the first 4 MiB and returns up to 500 results. Byte search accepts up to 128 bytes and stops each pass at 64 MiB, 200 matches or a comparison budget. Resume to scan farther.
- UnityFS opens individual files from standard bundles. LZ4/LZ4HC blocks are limited to 32 MiB each. LZMA, encrypted bundles and Unity serialized-object decoding are outside this release.
- DEX inspection lists structures at the table level. DEX 041 traversal is limited to 64 logical headers and the overall structure row cap. Unknown future versions and malformed structures are reported with warnings.

## Run your own copy

Use a browser with module workers, Web Crypto, and `DecompressionStream('deflate-raw')`. In the repository directory, run the following and visit [localhost:8000](http://localhost:8000).

```sh
python3 -m http.server 8000 --bind 127.0.0.1
```

On Windows, use `py -3` in place of `python3`. To publish a fork with GitHub Pages, select **Settings → Pages → Deploy from a branch → main → /(root)**.

## Development

Run the generated-fixture tests with Node.js 22 or later.

```sh
node --test tests/*.test.mjs
```

| Reference tool | What informed this release |
| --- | --- |
| [Android Studio APK Analyzer](https://developer.android.com/studio/debug/apk-analyzer#compare) | Compare package releases entry by entry and show size deltas. |
| [ImHex](https://github.com/WerWolv/ImHex#features) | Interpret the same bytes with different widths and byte orders. |
| [Kaitai Struct Web IDE](https://kaitai.io/news/2024/02/21/web-ide-improvements.html) | Link structure rows to byte ranges and preserve parsed rows when a later record fails. |
| [UABEA](https://github.com/nesrak1/UABEA) and [UnityPy issue 377](https://github.com/K0lb3/UnityPy/issues/377) | Open individual UnityFS members and use block flags even when packed and decoded sizes match. |
| [Apktool issue 2990](https://github.com/iBotPeaches/Apktool/issues/2990) and [AOSP AXML structures](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/libs/androidfw/include/androidfw/ResourceTypes.h) | Retain resource IDs and typed data when attribute names or resource labels are unavailable. |
| [Android zipalign](https://developer.android.com/tools/zipalign) and [APK Signature Scheme v2](https://source.android.com/docs/security/features/apksigning/v2) | Check actual payload offsets and report signing-block IDs with their positions. |

Format references include [ZIP](https://support.pkware.com/pkzip/appnote), [DEX](https://source.android.com/docs/core/runtime/dex-format), [ELF](https://gabi.xinuos.com/elf/), [PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), [UnityFS](https://reverseengineering.wiki/index.php/Format:Unity_asset_bundle_(UnityFS)), and [LZ4](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md).

## License

[Mozilla Public License 2.0](LICENSE).

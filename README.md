# GameAutopsy

GameAutopsy is a read-only game-file inspector that runs in your browser. Open the [GitHub Pages app](https://parzival235.github.io/GameAutopsy/) and drop in a file from your device. The app reads locally, processes files in a Web Worker, and saves reports or individual entries on request.

## Inspect a file

1. Choose a file or drag it onto the page.
2. In **Structure**, search for a path, type, or offset. Use **Open** on a ZIP entry to inspect its contents, or **Hex** to highlight its range in the current file. For ZIP entries, this shortcut highlights the fixed part of the local header.
3. In **Hex**, use a decimal or hexadecimal offset, step through 256-byte pages, or interpret the bytes at the current offset as signed integers, unsigned integers, or floats in either byte order.
4. In **Find bytes**, enter UTF-8 text or a hex sequence such as `55 6E ?? 74`. Click a result to highlight the match in Hex. **Continue search** resumes at the next unchecked offset.
5. Use **Strings**, **Compute SHA-256**, or **Download JSON** on the current file. **Save open entry** downloads the bytes of an opened ZIP, UnityFS or Godot PCK member to your device. Reports include any ZIP checks, string sample and SHA-256 you ran for the current file.

| Format | What GameAutopsy reads |
| --- | --- |
| ZIP, APK, APKS, XAPK, AAB, IPA, ZIP-based OBB | Single-disk ZIP and ZIP64 central directories. Open nested Stored or Deflate entries with CRC32 and size checks. |
| DEX | Headers, ID tables, class definition tables and map entries. DEX 041 containers can contain multiple logical files with offsets relative to the physical file. |
| ELF 32/64 | Architecture, byte order, entry address, segment permissions, sections, file offsets and 16 KiB LOAD alignment checks. |
| PE32 / PE32+ | Architecture, entry RVA, image base, sections and data directories. |
| UnityFS 6–8 | Header, block table and file directory for standard Raw, LZ4 and LZ4HC directories. Shows packed blocks and decoded file offsets. Open or save members that span Raw, LZ4 and LZ4HC blocks. |
| Android binary XML | UTF-8 and UTF-16LE pools, XML elements, attributes and typed values with exact record offsets. Manifest summary covers package, split, version, SDK levels and declared permissions. |
| Godot PCK v0–v4 | Standalone pack directories, paths, declared MD5, payload ranges and entry flags. Open or save ordinary unencrypted files. |
| IL2CPP metadata | Signature and selected header fields. |
| Any file | Hex, typed values, resumable UTF-8 and wildcard byte search, entropy, string samples and optional SHA-256. |

Offsets use bytes from the start of the current file unless labeled otherwise. ZIP structure offsets point to local headers. After opening an entry, **Format and source details** gives the local header and payload offsets in the parent archive. UnityFS file entries have a separate `streamOffset` into the decoded stream, while UnityFS block offsets point into the original bundle.

## Search an entire package

Open a ZIP-based package, UnityFS bundle, or standalone PCK and select **Inventory → Index root archive**. Filter by category or search for words from the filename, parent container path, row kind, or detected archive format. **Open** reconstructs the entry's location in the root package. The inventory stays available while you navigate its entries.

The index follows supported archive filename extensions, then checks the contents before traversing them. Category labels are filename hints. Extensionless containers require manual inspection. Indexing is bounded to four nested levels, 48 archive candidates including the root, 24,000 entries, 4 million UTF-16 code units of filename text, and 256 MiB of declared input. Coverage notes and JSON export identify skipped candidates and show how far the scan reached.

## Compare file bytes

Open any file or archive member, select **Byte diff**, and pick a comparison file from your device. The tool compares bytes at the same offsets, groups contiguous differences, and separately counts each file's extra tail bytes. Select a range to see both sides in hex with changed and missing bytes highlighted.

Each pass covers up to 128 MiB of offsets. **Continue comparison** resumes after the last pass, and **Compare from offset** starts at a decimal or hexadecimal address. The JSON export covers the current pass, keeps the first 2,048 ranges, and counts additional ranges. Insertions and deletions inside a file can shift later bytes and produce a long run of offset mismatches.

## Compare two releases

Open the older ZIP-based package, then choose **Compare archive** and pick the newer package. The comparison reads both central directories and shows added or removed paths, content metadata changes, packing changes, moved offsets, duplicate paths, and encrypted entries that need separate inspection.

The packed delta is the change in an entry's compressed payload size, excluding headers and padding. The comparison uses declared uncompressed sizes and CRC32 values to classify likely content differences. Use SHA-256 on an opened entry when you need a stronger equality check. The default **Inspect nested archives** option also compares changed or repacked archive members found at the same path in both versions. Use **Archive scope** to switch from the outer package to a compared split APK or another nested ZIP. **Nested comparison coverage** reports skipped paths and metadata matches. The JSON keeps each archive path as a separate array so the same entry name in different split APKs stays distinct.

Nested comparison follows archive extensions and exact case-sensitive paths to a maximum depth of three, up to 24 pairs, 20,000 nested diff rows, and 256 MiB of combined declared packed and unpacked input. Entries added or removed as whole archives appear at their parent level. Unchanged metadata outside an archive does not trigger reopening it. Clear the checkbox for a single-level comparison.

## Check an APK or ZIP

- **Check ZIP layout** compares local headers to the central directory and reports duplicate paths, overlapping header or payload ranges, and invalid metadata. For APKs it also checks stored payload alignment at 4 bytes and stored native-library payload alignment at 16 KiB.
- **Verify entry CRC32** independently reads and verifies eligible payloads. Reports include successful, failed and skipped counts. This check processes up to 512 entries and up to 256 MiB of combined declared packed and unpacked data. Each entry remains subject to the open limit.
- APK checks identify v2, v3 and v3.1 entries in the signing block and report their offsets. Signing-block findings describe structure only. Certificate trust, cryptographic signature validity, ZIP data-descriptor contents and installation compatibility are outside these checks.
- Open a native library to see its ELF LOAD alignment separately from its APK payload alignment.

## Privacy and limits

- Files and reports stay on the device. There is no backend, telemetry, or CDN dependency. To launch the app without internet access, serve a downloaded copy on localhost.
- ZIP directories are limited to 20,000 entries or 24 MiB of directory data. ZIP comparison requires two complete directories. Encrypted, split, and unsupported compression formats remain visible as metadata when the directory can be read.
- Nested ZIPs support six levels, up to 128 MiB per opened entry and 256 MiB total for entries held open. Whole-file SHA-256 supports up to 256 MiB. The string sampler scans the first 4 MiB and returns up to 500 results. Byte search accepts up to 128 bytes and stops each pass at 64 MiB, 200 matches or a comparison budget. Resume to scan farther.
- PCK inspection supports standalone packs. The directory read is limited to 24 MiB or 20,000 entries. Declared MD5 values come from the directory. Encrypted directories, special entry payloads (including encrypted, delta, removal and sparse entries), and executable-embedded packs are outside this release.
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
| [Android Studio APK Analyzer](https://developer.android.com/studio/debug/apk-analyzer#compare) and [bundletool](https://developer.android.com/tools/bundletool) | Compare entry-level size deltas and inspect same-path APKs within an APK set. |
| [Godot pack reader](https://github.com/godotengine/godot/blob/master/core/io/file_access_pack.cpp) and [GDRETools](https://github.com/GDRETools/gdsdecomp) | Interpret standalone PCK directory versions and distinguish raw payload offsets from record offsets. |
| [ImHex](https://github.com/WerWolv/ImHex#features) | Interpret the same bytes with different widths and byte orders. |
| [Kaitai Struct Web IDE](https://kaitai.io/news/2024/02/21/web-ide-improvements.html) | Link structure rows to byte ranges and preserve parsed rows when a later record fails. |
| [UABEA](https://github.com/nesrak1/UABEA) and [UnityPy issue 377](https://github.com/K0lb3/UnityPy/issues/377) | Open individual UnityFS members and use block flags even when packed and decoded sizes match. |
| [Apktool issue 2990](https://github.com/iBotPeaches/Apktool/issues/2990) and [AOSP AXML structures](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/libs/androidfw/include/androidfw/ResourceTypes.h) | Retain resource IDs and typed data when attribute names or resource labels are unavailable. |
| [Android zipalign](https://developer.android.com/tools/zipalign) and [APK Signature Scheme v2](https://source.android.com/docs/security/features/apksigning/v2) | Check actual payload offsets and report signing-block IDs with their positions. |

Format references include [ZIP](https://support.pkware.com/pkzip/appnote), [DEX](https://source.android.com/docs/core/runtime/dex-format), [ELF](https://gabi.xinuos.com/elf/), [PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), [UnityFS](https://reverseengineering.wiki/index.php/Format:Unity_asset_bundle_(UnityFS)), and [LZ4](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md).

## License

[Mozilla Public License 2.0](LICENSE).

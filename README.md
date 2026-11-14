# GameAutopsy

GameAutopsy is a read-only game-file inspector that runs in your browser. Open the [GitHub Pages app](https://parzival235.github.io/GameAutopsy/) and drop in a file from your device. The app reads locally, processes the file in a Web Worker, and downloads reports on request.

## Inspect a file

1. Choose a file or drag it onto the page.
2. In **Structure**, search for a path, type, or offset. Use **Open** on a ZIP entry to inspect its contents, or **Hex** to highlight its range in the current file. For ZIP entries, this shortcut highlights the fixed part of the local header.
3. In **Hex**, use a decimal or hexadecimal offset, step through 256-byte pages, or interpret the bytes at the current offset as signed integers, unsigned integers, or floats in either byte order.
4. Use **Strings**, **Compute SHA-256**, or **Download JSON** on the current file. A JSON report includes the string sample and SHA-256 if you computed them before downloading.

| Format | What GameAutopsy reads |
| --- | --- |
| ZIP, APK, APKS, XAPK, AAB, IPA, ZIP-based OBB | Single-disk ZIP and ZIP64 central directories. Open nested Stored or Deflate entries with CRC32 and size checks. |
| DEX | Headers, ID tables, class definition tables and map entries. DEX 041 containers can contain multiple logical files with offsets relative to the physical file. |
| ELF 32/64 | Architecture, byte order, entry address, segments, sections and file offsets. |
| PE32 / PE32+ | Architecture, entry RVA, image base, sections and data directories. |
| UnityFS 6–8 | Header, block table and file directory for standard Raw, LZ4 and LZ4HC directories. Shows packed blocks and decoded file offsets. |
| Android binary XML | Chunk types, sizes, offsets and source lines when present. |
| Godot PCK / IL2CPP metadata | Signature and selected header fields. |
| Any file | Hex, typed values, entropy samples, ASCII and UTF-16LE string samples, and optional SHA-256. |

Offsets use bytes from the start of the current file unless labeled otherwise. ZIP structure offsets point to local headers. After opening an entry, **Format and source details** gives the local header and payload offsets in the parent archive. UnityFS file entries have a separate `streamOffset` into the decoded stream, while UnityFS block offsets point into the original bundle.

## Compare two releases

Open the older ZIP-based package, then choose **Compare archive** and pick the newer package. The comparison reads both central directories and shows added or removed paths, content metadata changes, packing changes, moved offsets, duplicate paths, and encrypted entries that need separate inspection.

The packed delta is the change in an entry's compressed payload size, excluding headers and padding. The comparison uses declared uncompressed sizes and CRC32 values to classify likely content differences. Use SHA-256 on an opened entry when you need a stronger equality check. Comparison is scoped to the current ZIP level and can be downloaded as JSON.

## Privacy and limits

- Files and reports stay on the device. There is no backend, telemetry, or CDN dependency. To launch the app without internet access, serve a downloaded copy on localhost.
- ZIP directories are limited to 20,000 entries or 24 MiB of directory data. ZIP comparison requires two complete directories. Encrypted, split, and unsupported compression formats remain visible as metadata when the directory can be read.
- Nested ZIPs support six levels, up to 128 MiB per opened entry and 256 MiB total for entries held open. Whole-file SHA-256 supports up to 256 MiB. The string sampler scans the first 4 MiB and returns up to 500 results.
- UnityFS inspection inventories blocks and files. Extraction and serialized asset decoding are outside this release. LZMA and encrypted UnityFS directories are reported as unsupported.
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
| [AssetRipper](https://github.com/AssetRipper/AssetRipper) and [UnityPy](https://github.com/K0lb3/UnityPy) | Identify the difference between bundle storage, the decoded stream, and serialized assets. |

Format references include [ZIP](https://support.pkware.com/pkzip/appnote), [DEX](https://source.android.com/docs/core/runtime/dex-format), [ELF](https://gabi.xinuos.com/elf/), [PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), [UnityFS](https://reverseengineering.wiki/index.php/Format:Unity_asset_bundle_(UnityFS)), and [LZ4](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md).

## License

[Mozilla Public License 2.0](LICENSE).

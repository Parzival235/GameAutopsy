# GameAutopsy User Guide

[Project overview](../README.md) · [Open GameAutopsy](https://parzival235.github.io/GameAutopsy/)

GameAutopsy is a read-only game-file inspector that runs in your browser. Open the [GitHub Pages app](https://parzival235.github.io/GameAutopsy/) and drop in a file from your device. The app reads locally, processes files in a Web Worker, and saves reports or individual entries on request.

## Inspect a file

1. Choose a file or drag it onto the page.
2. In **Structure**, search for a path, type, or offset. Use **Open** on a supported entry to inspect its contents, or **Hex** to highlight its range in the current file. For ZIP entries, this shortcut highlights the fixed part of the local header.
3. In **Hex**, use a decimal or hexadecimal offset, step through 256-byte pages, or interpret the bytes at the current offset as signed integers, unsigned integers, or floats in either byte order.
4. In **Find bytes**, enter UTF-8 text or a hex sequence such as `55 6E ?? 74`. Click a result to highlight the match in Hex. **Continue search** resumes at the next unchecked offset.
5. Use **Strings**, **Compute SHA-256**, or **Current file JSON** on the current file. **Save open entry** downloads the exact bytes of an opened archive entry or Unity object to your device. Reports include any ZIP checks, string sample and SHA-256 you ran for the current file.

| Format | What GameAutopsy reads |
| --- | --- |
| ZIP, APK, APKS, XAPK, AAB, IPA, ZIP-based OBB | Single-disk ZIP and ZIP64 central directories. Open nested Stored or Deflate entries with CRC32 and size checks. |
| DEX | Headers, ID tables, class definition tables and map entries. DEX 041 containers can contain multiple logical files with offsets relative to the physical file. |
| ELF 32/64 | Architecture, byte order, entry address, segment permissions, sections, file offsets and 16 KiB LOAD alignment checks. |
| PE32 / PE32+ | Architecture, entry RVA, image base, sections and data directories. |
| UnityFS 6–8 | Header, block table and file directory. Open members from Raw, LZMA, LZ4 and LZ4HC blocks. |
| Unity serialized files 17–26 | Object table with exact 64-bit Path IDs, class IDs, type hashes, metadata records, payload ranges and external file references. Decode fields from embedded TypeTrees in versions 17–23. |
| Android binary XML | UTF-8 and UTF-16LE pools, XML elements, attributes and typed values with exact record offsets. Manifest summary covers package, split, version, SDK levels and declared permissions. |
| Godot PCK v0–v4 | Standalone pack directories, paths, declared MD5, payload ranges and entry flags. Open or save ordinary unencrypted files. |
| IL2CPP metadata | Signature and selected header fields. |
| Any file | Hex, typed values, resumable UTF-8 and wildcard byte search, entropy, Unicode string scans and optional SHA-256. |

Offsets use bytes from the start of the current file unless labeled otherwise. ZIP structure offsets point to local headers. After opening an entry, **Format and source details** gives the local header and payload offsets in the parent archive. UnityFS file entries have a separate `streamOffset` into the decoded stream, while UnityFS block offsets point into the original bundle.

## Export a full analysis report

Click **Export full JSON** to create one `.gameautopsy-full.json` file for the current root and files opened in this session. The export runs any missing standard analyses on the active file: a first hex preview with both byte orders, a bounded UTF-8 and ASCII-wide string sample, and SHA-256 up to 256 MiB. To include a digest for a larger file, use **Compute SHA-256** first. The worker hashes 1 MiB slices, shows hashed bytes, and supports **Cancel SHA-256** during that manual operation. For a ZIP, it also runs layout checks and bounded CRC32 verification. For a supported root archive, it adds the inventory. **Current file JSON** still downloads just the open file's existing report.

The combined JSON includes the file reports, inventory, and recorded byte searches, hex previews, ZIP checks and archive or byte comparisons. Run searches and comparisons before export to include those inputs and results. Each recorded operation has a source path and a route of member indices, which distinguish duplicate paths. `automatic` records completed, reused, skipped or failed checks, and `omitted` counts optional history beyond the 16 Mi-character shared budget or the 96-item cap per history collection. The active and root reports and latest inventory are included separately from that history budget. Opening a different root starts a new report session. Exports are assembled in the Web Worker.

While the tool is busy, the activity strip shows the current stage. When known, its counters measure work within that stage, such as ZIP entries reviewed or bytes read for hashing. You can use the breadcrumb links to return directly to an open parent.

## Locate a Unity object

1. Open a Unity serialized file such as `sharedassets0.assets`, or open a serialized member (often `CAB-…`) from a UnityFS bundle.
2. In **Structure**, filter by a class name such as `Texture2D` or `MonoBehaviour`, an exact Path ID, or an external file path. Expand **Format and source details** for the engine version, byte order, class counts, and coverage.
3. Use **Fields** on a supported object to inspect strings, numbers, arrays, nested fields and references. Filter by field path, type or value, or use **Hex** on a field to highlight its bytes in the serialized file. **Follow object** opens the fields of a uniquely indexed local reference.
4. Use **Save TextAsset bytes** to extract a TextAsset's declared `m_Script` payload as a binary file. Choose **Open → Save open entry** for the raw serialized object. **Export full JSON** includes the fields already inspected, subject to the report retention limits.

External reference rows report the declared path, GUID bytes and one-based File ID. Field offsets refer to the serialized file. For a UnityFS member, they are relative to the decoded member. **Record** still highlights the object's metadata record.

Field decoding uses inline TypeTrees in serialized files 17–23. Objects with stripped or externally stored trees, managed references, newer tree layouts, and texture, audio or mesh conversion are outside this decoder's coverage. Managed-reference fields can stop decoding after an earlier usable prefix. Limits are 1 MiB of tree data, 12,000 tree nodes, 48 levels, 5,000 output rows and an 8 MiB payload read. Known byte ranges can still be recorded and saved without loading the entire payload.

## Compare Unity objects across versions

Open the baseline Unity serialized file, including one opened from a bundle. In **Unity diff**, choose the new serialized file or a UnityFS bundle. For a bundle, choose the member to compare. Leave **Path ID** blank for a bulk pass or enter one signed 64-bit decimal ID. Choose **Compare Unity files**.

The comparison pairs unique Path IDs in the two selected files. A Path ID is local to its serialized file. If a rebuild assigns new IDs, these results describe added and removed IDs. Object names are never used as substitute matches.

- Equal byte ranges can be reported separately from objects that moved. Both sides' offsets refer to their own serialized file.
- When supported TypeTrees are available, field evidence contains the field path, value and offset on each side. Data fields are compared at their declared byte ranges, including bytes beyond the on-screen preview. A changed external table can change a pointer target even when the object's bytes are identical. Resolved external pointers are compared using their declared path, GUID, reference type and target ID.
- Duplicate IDs, unreadable ranges and potentially missing objects in an incomplete index are reported as unresolved. Partial field comparisons can prove a specific change. They cannot establish that every field matches.
- **Download Unity diff JSON** includes object and field evidence, source paths, coverage and limits. The comparison is also recorded in **Export full JSON**.

A run checks up to 768 payload pairs, with an 8 MiB per-object limit and a 128 MiB shared budget for payload and field reads. The JSON includes counts for omitted rows and field evidence. Use the **Path ID** filter to check a specific object outside the bulk pass.

## Search an entire package

Open a ZIP-based package, UnityFS bundle, or standalone PCK and select **Inventory → Index root archive**. Filter by category or search for words from the filename, parent container path, row kind, or detected archive format. **Open** reconstructs the entry's location in the root package. The inventory stays available while you navigate its entries.

Open **Search file contents**, choose UTF-8 or hex, and run **Search filtered contents**. It searches decoded payloads matching the current inventory path and category filters across all pages. Recognized container wrappers are excluded from the search so you can inspect their indexed children. Click an offset to open the corresponding entry in Hex and highlight the match. Offsets are relative to that decoded entry.

Each search pass checks up to 100 entries, 16 MiB of candidate offsets, 150 matches, 8 million byte comparisons and 192 MiB of read/decode work. Members over 32 MiB packed or decoded are skipped. **Continue search** uses the original pattern and filters, resuming at the next unchecked offset or entry. **Download search JSON** saves the current pass with source offsets and coverage. **Export full JSON** records passes in the session history. Check both the inventory and search coverage before treating an empty result as evidence of absence.

Select individual rows or use **Select page** to pick readable entries on the current page. The selection stays active when you change filters or pages. Use **Download selected ZIP** to save up to 100 entries with a combined decoded size of up to 64 MiB. The worker also caps packed, decoded and output checksum work at 192 MiB. Entries that exceed a budget or fail to decode appear in the export manifest. If all selected entries are skipped, the app saves the manifest as JSON.

The output contains the raw member payloads in separate folders for each source container. Export paths are sanitized, and colliding names go into distinct folders. `gameautopsy-manifest.json` retains the original filenames, container paths, routes and offsets. ZIP members are checked against their stored CRC32. UnityFS and Godot PCK members are checked for readable ranges and decoded size. The PCK MD5 in the manifest is a declared value. The export is stored as an uncompressed ZIP.

The index follows supported archive filename extensions, then checks the contents before traversing them. Category labels are filename hints. Extensionless containers require manual inspection. Indexing is bounded to four nested levels, 48 archive candidates including the root, 24,000 entries, 4 million UTF-16 code units of filename text, and 256 MiB of declared input. Coverage notes and JSON export identify skipped candidates and show how far the scan reached.

## Compare file bytes

Open any file or archive member, select **Byte diff**, and pick a comparison file from your device. The tool compares bytes at the same offsets, groups contiguous differences, and separately counts each file's extra tail bytes. Select a range to see both sides in hex with changed and missing bytes highlighted.

Each pass covers up to 128 MiB of offsets. **Continue comparison** resumes after the last pass, and **Compare from offset** starts at a decimal or hexadecimal address. The JSON export covers the current pass, keeps the first 2,048 ranges, and counts additional ranges. Insertions and deletions inside a file can shift later bytes and produce a long run of offset mismatches.

## Compare two releases

Open the older ZIP-based package, then choose **Compare archive** and pick the newer package. The default comparison reads both central directories and shows added or removed paths, content metadata changes, packing changes, moved offsets, duplicate paths, and encrypted entries. Packed delta measures the size of the compressed payload, excluding headers and padding.

Enable **Verify entry bytes** before selecting the newer package to compare decoded payloads at shared, unique paths. The worker checks each local header, decoded size and CRC32, then compares the decoded bytes directly. A row can show **Payload bytes differ** even when the declared sizes and CRC32 match. The first difference is relative to the decoded entry. Appended or removed tails are included. Enable **Show verified matches** to review confirmed equal entries. Unreadable payloads and skipped paths are counted separately from verified matches.

**Inspect nested archives** looks inside changed or repacked same-path ZIP members. In verification mode it also opens archive members with equal metadata and different verified bytes, and skips confirmed byte-for-byte matches. **Archive scope** switches between the outer package and a compared split APK or nested ZIP. The JSON records paths as arrays and includes content verdicts and limits for each scope.

Nested traversal follows case-sensitive names to a maximum depth of three, up to 24 archive pairs, 20,000 nested result rows, and 256 MiB of declared packed plus unpacked input. Verification shares a separate 512-pair and 192 MiB input budget across scopes. It attempts up to 256 pairs per scope. Each packed or decoded payload must be at most 32 MiB. Stored and Deflate entries are supported. A match describes the bytes of a decoded entry. APK signature validity and installability require separate checks.

## Compare and save individual entries

In **Comparison**, click **Diff bytes** on a two-sided entry or enter its exact, case-sensitive name in **Exact entry path**. The lookup uses the selected **Archive scope**, including compared split APKs, and works for paths that were omitted from the change list because their metadata matched. The byte diff reads the decoded contents, highlights differences at matching offsets, and opens at the first differing range.

**Save baseline entry** and **Save candidate entry** save the checked payload on each side. **Archive comparison** returns to the same scope and filtered table. The byte-diff export and full report record the package names, the nested archive path, and each entry's local header and data offsets relative to its immediate ZIP container.

This on-demand comparison checks each local header, decoded size and CRC32. It supports Stored and Deflate entries up to 128 MiB packed and decoded per entry. Reopening the two paths has a combined 384 MiB input budget and at most 128 MiB of Deflate output, including intermediate archives. Duplicate names must be resolved outside this paired view.

## Find strings in binary files

Open **Strings**, choose **UTF-8**, **UTF-16LE**, **UTF-16BE**, or **ASCII**, set a hexadecimal or decimal offset, and select **Scan strings**. UTF-16 code units are aligned from the chosen offset. The minimum length counts Unicode characters. Each row gives the byte offset and links to the matching span in **Hex**.

Each pass scans approximately 4 MiB and keeps up to 500 results. **Continue scan** resumes with the same encoding and length. Very long strings can appear as linked fragments across consecutive passes. JSON records each pass's start, end, continuation and full byte spans. The automatic full-report sample covers the first 4 MiB using UTF-8 and ASCII-compatible UTF-16LE at both alignments. Encodings are selected explicitly, so UTF-16 can still produce readable-looking sequences in binary data.

## Inspect an Android APK set

Open an APK, APKS, XAPK, or a ZIP/APKM containing APK members. Select **APK set → Inspect APK set**. Optionally choose the device ABI to flag when native libraries for that architecture are absent from an inspected group.

- The inspector reads each APK's own binary manifest and reports package, split ID, full version code, declared split dependencies, and native libraries by ABI. **Find APK or native library** can locate Unity's `libil2cpp.so` across the set.
- Bundletool `toc.pb` groups split APKs into variants and keeps standalone candidates separate. The XAPK reader handles manifests listing APKs in `split_apks[].file`. Without a usable TOC, group checks use the available manifests and report ambiguous base choices.
- APK Signature Scheme v2/v3/v3.1 certificate SHA-256 values are extracted from declared signer records. The inspector compares matching schemes and SDK ranges. Signature validity, signing lineage, trust, and Android device-specific variant selection are outside this check.
- Metadata inspection is limited to 128 APKs and 384 MiB of declared packed-plus-unpacked compressed members. Stored APK members can be read by range without verifying the container CRC. Unreadable members are listed separately, and absence checks use **Unknown** when coverage is incomplete.
- **Download APK set JSON** saves the standalone report. **Export full JSON** includes the root's APK set report and automatically runs the default check if needed.

## Check an APK or ZIP

- **Check ZIP layout** compares local headers to the central directory and reports duplicate paths, overlapping header or payload ranges, and invalid metadata. For APKs it also checks stored payload alignment at 4 bytes and stored native-library payload alignment at 16 KiB.
- **Verify entry CRC32** independently reads and verifies eligible payloads. Reports include successful, failed and skipped counts. This check processes up to 512 entries and up to 256 MiB of combined declared packed and unpacked data. Each entry remains subject to the open limit.
- APK checks identify v2, v3 and v3.1 entries in the signing block and report their offsets. Signing-block findings describe structure only. Certificate trust, cryptographic signature validity, ZIP data-descriptor contents and installation compatibility are outside these checks.
- Open a native library to see its ELF LOAD alignment separately from its APK payload alignment.

## Privacy and limits

- Files and reports stay on the device. There is no backend, telemetry, or CDN dependency. To launch the app without internet access, serve a downloaded copy on localhost.
- ZIP directories are limited to 20,000 entries or 24 MiB of directory data. ZIP comparison requires two complete directories. Encrypted, split, and unsupported compression formats remain visible as metadata when the directory can be read.
- Nested ZIPs support six levels, up to 128 MiB per opened entry and 256 MiB total for entries held open. Byte search accepts up to 128 bytes and stops each pass at 64 MiB, 200 matches or a comparison budget. Resume to scan farther.
- PCK inspection supports standalone packs. The directory read is limited to 24 MiB or 20,000 entries. Declared MD5 values come from the directory. Encrypted directories, special entry payloads (including encrypted, delta, removal and sparse entries), and executable-embedded packs are outside this release.
- UnityFS directory data is capped at 24 MiB. Compressed blocks are limited to 32 MiB each, and opened members to 128 MiB. Encrypted bundles are outside this release. Unity serialized inspection is limited to 24 MiB of metadata and 20,000 structure rows per file.
- DEX inspection lists structures at the table level. DEX 041 traversal is limited to 64 logical headers and the overall structure row cap. Unknown future versions and malformed structures are reported with warnings.

## Run your own copy

Use a browser with module workers, Web Crypto, and `DecompressionStream('deflate-raw')`. In the repository directory, run the following and visit [localhost:8000](http://localhost:8000).

```sh
python3 -m http.server 8000 --bind 127.0.0.1
```

On Windows, use `py -3` in place of `python3`. To publish a fork with GitHub Pages, select **Settings → Pages → Deploy from a branch → main → /(root)**.

## Development

Run the generated-fixture tests with Node.js 22 or later. GitHub Actions runs the same suite on Node.js 22 and 24 on pushes to main and on pull requests.

```sh
node --test tests/*.test.mjs
```

| Reference tool | What informed this release |
| --- | --- |
| [Android Studio APK Analyzer](https://developer.android.com/studio/debug/apk-analyzer#compare) and [bundletool](https://developer.android.com/tools/bundletool) | Compare entry-level size deltas and inspect same-path APKs within an APK set. |
| [Godot pack reader](https://github.com/godotengine/godot/blob/master/core/io/file_access_pack.cpp) and [GDRETools](https://github.com/GDRETools/gdsdecomp) | Interpret standalone PCK directory versions and distinguish raw payload offsets from record offsets. |
| [GNU strings](https://sourceware.org/binutils/docs/binutils/strings.html) | Select an encoding and minimum character length while preserving file offsets. |
| [ImHex](https://github.com/WerWolv/ImHex#features) | Interpret the same bytes with different widths and byte orders. |
| [Kaitai Struct Web IDE](https://kaitai.io/news/2024/02/21/web-ide-improvements.html) | Link structure rows to byte ranges and preserve parsed rows when a later record fails. |
| [UABEA](https://github.com/nesrak1/UABEA) and [UnityPy issue 377](https://github.com/K0lb3/UnityPy/issues/377) | Open individual UnityFS members and use block flags even when packed and decoded sizes match. |
| [UnityDataTools](https://github.com/Unity-Technologies/UnityDataTools) and [UnityPy](https://github.com/K0lb3/UnityPy) | Validate Unity object and external reference tables against published engine fixtures and independent format readers. |
| [Apktool issue 2990](https://github.com/iBotPeaches/Apktool/issues/2990) and [AOSP AXML structures](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/libs/androidfw/include/androidfw/ResourceTypes.h) | Retain resource IDs and typed data when attribute names or resource labels are unavailable. |
| [Android zipalign](https://developer.android.com/tools/zipalign) and [APK Signature Scheme v2](https://source.android.com/docs/security/features/apksigning/v2) | Check actual payload offsets and report signing-block IDs with their positions. |

The [Unity common-string table](../vendor/unity-common-strings/LICENSE) is adapted from AssetStudio under MIT. The vendored [lzma-purejs decoder](../vendor/lzma/LICENSE) runs offline. SHA-256 uses the [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) block and padding rules.

Format references include [ZIP](https://support.pkware.com/pkzip/appnote), [DEX](https://source.android.com/docs/core/runtime/dex-format), [ELF](https://gabi.xinuos.com/elf/), [PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), [UnityFS](https://reverseengineering.wiki/index.php/Format:Unity_asset_bundle_(UnityFS)), and [LZ4](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md).

## License

[Mozilla Public License 2.0](../LICENSE).

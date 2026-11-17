# GameAutopsy

Find what changed between two builds of a game. Inspect APKs, Unity assets, Godot packs and other binary files in your browser. **No account, installation or file uploads.**

**[Open GameAutopsy](https://parzival235.github.io/GameAutopsy/)** · [Try Unity field diff](https://parzival235.github.io/GameAutopsy/?demo=unity) · [Try nested ZIP diff](https://parzival235.github.io/GameAutopsy/?demo=archive) · [User guide](docs/manual.md)

In the Unity demo, object **Path ID 3** changes from layer **0** to **7**. Open **Hex** on the baseline field or [view the example comparison report](docs/example-unity-diff.json) for both byte offsets and comparison coverage. The ZIP demo finds the change inside `assets/config.zip` and lets you open both versions of `settings.json`. Both demos generate synthetic files in your browser.

## What you can inspect

| Task | What GameAutopsy shows |
| --- | --- |
| Compare two APKs, APK sets or ZIP packages | Added, removed and repacked paths, nested archives, and optional byte-for-byte verification of decoded entries. |
| Inspect a Unity bundle or compare its assets | UnityFS members, serialized object Path IDs and references. Supported embedded TypeTrees reveal changed fields and their byte offsets. |
| Inspect Android and native binaries | APK split dependencies and ABIs, binary Android manifests, ZIP alignment, DEX tables, ELF segments and PE sections. |
| Trace and export evidence | Hex, resumable strings and byte search, SHA-256, entry downloads and one JSON report for the analysis session. |

GameAutopsy reads files without modifying them. It compares Unity objects by Path ID within each serialized file. See the [supported formats, verification limits and self-hosting instructions](docs/manual.md).

## Development

[![Tests](https://github.com/Parzival235/GameAutopsy/actions/workflows/tests.yml/badge.svg)](https://github.com/Parzival235/GameAutopsy/actions/workflows/tests.yml)

Run `node --test tests/*.test.mjs` with Node.js 22 or later. To report a parsing issue, include the format, browser, GameAutopsy version and exact steps. Share a small sample only if you have permission to publish it. [Open an issue](https://github.com/Parzival235/GameAutopsy/issues/new).

[Mozilla Public License 2.0](LICENSE)

# Changelog

## 0.12.1

- Added one-click Unity field and nested ZIP comparison demos. The app generates synthetic inputs in the browser and runs them through the same worker as local files.
- Published a sample Unity comparison report with a changed field, a relocated object with equal bytes, and two object IDs that appear on only one side.
- Reworked the repository overview and moved the detailed guide to [docs/manual.md](docs/manual.md). Updated the app's search and sharing metadata.

## 0.12.0

- Added Unity serialized object comparison by Path ID, with before/after field values and byte offsets when supported embedded TypeTrees are present.
- Separated relocated equal payloads from field, byte and metadata changes. Reports show coverage, unresolved objects and comparison limits.

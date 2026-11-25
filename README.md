# searxh

Fast desktop file indexer, fuzzy/frecency/favor search CLI, virtual folder filter, and inspector built on [`jwalk`](https://crates.io/crates/jwalk) and [`nucleo-matcher`](https://crates.io/crates/nucleo-matcher).

## Features

- **Parallel scan + smart pruning (`jwalk`)**: skips `.git`, `node_modules`, `.cache`, `.local/share`, `.omp`, `go/pkg`, `.venvs`, browser/game blobs during `readdir` while preserving useful dotfiles (`.config`, `.zshrc`, `.local/bin`).
- **Compact Binary Index V3 (`index.bin`)**: 42-byte header (`built_at`, monotonic `generation`, `config_fingerprint`, `count`, `string_bytes`), fixed 28-byte entry records with precomputed basename offsets, and a single contiguous UTF-8 string arena. Queries validate UTF-8 once and search borrowed slices with bounded Top-K selection (`IndexSnapshot`).
- **Coordinated single-writer lifecycle**: advisory file locks (`.writer.lock`, `.watch.lock`, `state.json.lock`) serialize `index`, cold rebuilds, and watcher publications across full scan + atomic publish windows.
- **Non-blocking frontend mode (`--require-index`)**: returns immediately with `status: "indexing"` and empty items while triggering background refresh when the index is cold or invalidated.
- **Two-tier fuzzy & multi-signal ranking**: primary match tier (`exact basename > prefix basename > fuzzy basename > fuzzy path`) protected from secondary personal relevance boosts (`priority_roots`, mtime recency, frecency `touch`, pinned favorites `pin`).
- **Virtual folders (`@name`)**: built-in `@pinned`, `@recent`, `@modified`, `@images`, `@docs`, `@videos`, `@audio`, `@screenshots`, `@downloads` plus custom `[virtual.<name>]` rules in `config.toml`.
- **Single-call inspector (`inspect`)**: content-sniffed MIME detection, UTF-8 encoding detection, symlink target/broken inspection, directory summaries (`dir_summary`), image dimensions + EXIF metadata, configurable preview caps, and non-blocking guards against special files (FIFOs, sockets, device nodes).
- **Real-time watcher (`watch`)**: registers `NonRecursive` `inotify` watches before startup reconciliation, caps continuous-burst latency via a maximum publish interval, and reloads `config.toml` changes automatically.

## Usage

```bash
# Build or refresh the binary index
searxh index

# Non-blocking launcher query (versioned schema-v1 JSON envelope + fresh Top-K stat)
searxh query --envelope --require-index --stat -n 25 -- lfp

# Backward-compatible bare JSON array output
searxh query --json --stat -n 25 -- lfp

# List or filter virtual folders
searxh query --envelope -- "@"
searxh query --envelope -n 25 -- "@screenshots"
searxh query --envelope -n 25 -- "@dots media"

# Live scan without touching the cache
searxh query --live --root ~/projects/searxh --json -- mod

# Record opens (frecency) and manage pinned favorites
searxh touch -- ~/Documents/notes.md
searxh pin -- ~/Documents/System/linux-dots/setup
searxh unpin -- ~/Documents/System/linux-dots/setup
searxh pins --json

# Inspect selected file / directory / symlink / image (+ EXIF)
searxh inspect --envelope -- ~/Pictures/photo.jpg

# Optional incremental watcher service
searxh watch
```

## Configuration (`~/.config/searxh/config.toml`)

```toml
roots = ["$HOME"]
priority_roots = ["~/Documents", "~/projects", "~/Downloads", "~/Pictures", "~/Screenshots", "~/.config"]
index_ttl_sec = 180
watch_debounce_ms = 300
inspect_max_bytes = 262144
inspect_max_lines = 2000
inspect_max_entries = 40

[virtual.dots]
label = "Dotfiles"
roots = ["~/Documents/System/linux-dots", "~/.config"]
sort = "mtime"

[virtual.pdfs]
label = "PDF Documents"
extensions = ["pdf"]
sort = "mtime"
```

## Versioned JSON Contract (`--envelope`, `schema_version = 1`)

- `query --envelope` returns:
  ```json
  {
    "schema_version": 1,
    "tool": "searxh",
    "tool_version": "0.5.0",
    "command": "query",
    "status": "ready",
    "index_generation": 12,
    "index_built_at": 1700000000,
    "config_fingerprint": 1234567890,
    "items": []
  }
  ```
  When `--require-index` is passed and no valid index exists yet, `status` is `"indexing"`, `items` is `[]`, and a background index refresh is spawned (unless `--no-refresh` is set).
- `inspect --envelope` wraps `InspectResult` in `{ schema_version: 1, tool: "searxh", tool_version, command: "inspect", result }` containing `{ path, name, kind, mime?, encoding?, symlink_target?, symlink_broken?, resolved_path?, category, size, mtime, mode, preview_kind, text?, truncated?, lines?, total_entries?, dir_summary?, entries?, image? }`.
- Legacy `--json` remains supported for bare array/object consumers.

## Benchmark

```bash
cargo build --release --locked
cargo run --release --example bench_searxh -- 150000
```

## License

MIT

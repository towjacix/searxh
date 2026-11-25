# searxh

Fast desktop file indexer, fuzzy/frecency/favor search CLI, virtual folder filter, and inspector built on [`jwalk`](https://crates.io/crates/jwalk) and [`nucleo-matcher`](https://crates.io/crates/nucleo-matcher).

## Features

- **Parallel scan + smart pruning (`jwalk`)**: skips `.git`, `node_modules`, `.cache`, `.local/share`, `.omp`, `go/pkg`, `.venvs`, browser/game blobs during `readdir` while preserving useful dotfiles (`.config`, `.zshrc`, `.local/bin`).
- **Compact binary index (`index.bin`)**: sub-10ms queries with atomic writes and non-blocking lazy background refresh when stale.
- **Fuzzy & multi-signal ranking**: `nucleo-matcher` paired with basename exact/prefix bonuses, priority-root bias, mtime recency, zoxide-style frecency (`touch`), and pinned favorites (`pin`).
- **Virtual folders (`@name`)**: built-in `@pinned`, `@recent`, `@modified`, `@images`, `@docs`, `@videos`, `@audio`, `@screenshots`, `@downloads` plus custom `[virtual.<name>]` rules in `config.toml`.
- **Single-call inspector (`inspect`)**: fresh stat, UTF-8-safe text preview (sniffed by content so extensionless scripts like `setup` or `PKGBUILD` preview cleanly), directory entry listing, image dimensions, and EXIF camera metadata.
- **Optional real-time watcher (`watch`)**: registers `NonRecursive` `inotify` watches only on pruned directories and writes `index.bin` atomically after debouncing.

## Usage

```bash
# Build or refresh the binary index
searxh index

# Fuzzy search with fresh stat metadata on Top-K hits
searxh query --json --stat -n 25 -- lfp

# List or filter virtual folders
searxh query --json -- "@"
searxh query --json -n 25 -- "@screenshots"
searxh query --json -n 25 -- "@dots media"

# Live scan without touching the cache (great for a specific project directory)
searxh query --live --root ~/projects/searxh --json -- mod

# Record opens (frecency) and manage pinned favorites
searxh touch -- ~/Documents/notes.md
searxh pin -- ~/Documents/System/linux-dots/setup
searxh unpin -- ~/Documents/System/linux-dots/setup
searxh pins --json

# Inspect selected file / directory / image (+ EXIF)
searxh inspect --json -- ~/Pictures/photo.jpg

# Optional incremental watcher service
searxh watch
```

## Configuration (`~/.config/searxh/config.toml`)

```toml
roots = ["$HOME"]
priority_roots = ["~/Documents", "~/projects", "~/Downloads", "~/Pictures", "~/Screenshots", "~/.config"]
index_ttl_sec = 180

[virtual.dots]
label = "Dotfiles"
roots = ["~/Documents/System/linux-dots", "~/.config"]
sort = "mtime"

[virtual.pdfs]
label = "PDF Documents"
extensions = ["pdf"]
sort = "mtime"
```

## Quickshell Launcher Integration

- Query returns JSON array items `{ path, name, kind, category, size, mtime, score, pinned, ... }` or `{ kind: "virtual", name: "@...", title, subtitle, count, completion }` when completing `@`.
- `inspect --json -- <path>` returns `{ path, name, kind, category, size, mtime, mode, preview_kind, text?, truncated?, lines?, entries?, image? }`, replacing separate `stat` + `dd` subprocesses.

## License

MIT

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use searxh::config::{Config, ExclusionRules, ResolvedPaths, expand_tilde};
use searxh::index::{now_secs, publish_index, read_index, spawn_background_refresh};
use searxh::inspect::{InspectOptions, inspect_path};
use searxh::scanner::{ScanOptions, scan_roots};
use searxh::search::{QueryOptions, QueryOutputItem, TypeFilter, search};
use searxh::state::StateStore;
use searxh::watch::run_watch;
use serde::Serialize;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Parser)]
#[command(
    name = "searxh",
    version,
    about = "Fast desktop file search CLI built on jwalk & nucleo"
)]
struct Cli {
    #[arg(long, global = true, help = "Override config.toml path")]
    config: Option<PathBuf>,

    #[arg(long, global = true, help = "Override index.bin cache path")]
    cache: Option<PathBuf>,

    #[arg(long, global = true, help = "Override state.json path")]
    state: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliTypeFilter {
    All,
    File,
    Dir,
}

impl From<CliTypeFilter> for TypeFilter {
    fn from(value: CliTypeFilter) -> Self {
        match value {
            CliTypeFilter::All => Self::All,
            CliTypeFilter::File => Self::File,
            CliTypeFilter::Dir => Self::Dir,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Search indexed files (or run --live scan) and @virtual folders
    Query {
        /// Output JSON array
        #[arg(long)]
        json: bool,

        /// Null-delimited path output (for xargs -0 / fzf --read0)
        #[arg(long)]
        print0: bool,

        /// Maximum number of results
        #[arg(short = 'n', long, default_value_t = 25)]
        limit: usize,

        /// Call symlink_metadata on final Top-K results
        #[arg(long)]
        stat: bool,

        /// Skip index cache and walk roots directly via jwalk
        #[arg(long)]
        live: bool,

        /// Disable stale-index background refresh
        #[arg(long)]
        no_refresh: bool,

        /// Override search roots for this query (repeatable)
        #[arg(long = "root")]
        roots: Vec<String>,

        /// Filter entry type
        #[arg(long = "type", value_enum, default_value_t = CliTypeFilter::All)]
        entry_type: CliTypeFilter,

        /// Search query (supports @virtual prefixes); trailing tokens joined by spaces
        #[arg(trailing_var_arg = true)]
        query: Vec<String>,
    },

    /// Build or refresh the binary index cache via jwalk
    Index {
        /// Override roots to index (repeatable)
        #[arg(long = "root")]
        roots: Vec<String>,

        /// Skip stat() during walk for faster path-only scans
        #[arg(long)]
        no_stat: bool,

        /// Print summary as JSON
        #[arg(long)]
        json: bool,
    },

    /// Inspect metadata, text preview, directory entries, or image EXIF of a single path
    Inspect {
        /// Output JSON object
        #[arg(long)]
        json: bool,

        /// Max bytes to read for text previews
        #[arg(long, default_value_t = 262_144)]
        max_bytes: usize,

        /// Max lines for text previews
        #[arg(long, default_value_t = 2000)]
        max_lines: usize,

        /// Max entries listed when path is a directory
        #[arg(long, default_value_t = 40)]
        max_entries: usize,

        /// Include raw GPS coordinates in EXIF output (hidden by default)
        #[arg(long)]
        gps: bool,

        /// Path to inspect
        path: PathBuf,
    },

    /// Record a file/directory access to boost frecency
    Touch { path: PathBuf },

    /// Pin a path as a favorite
    Pin { path: PathBuf },

    /// Remove a path from pinned favorites
    Unpin { path: PathBuf },

    /// List pinned favorite paths
    Pins {
        #[arg(long)]
        json: bool,
    },

    /// List configured and built-in @virtual folders
    Virtuals {
        #[arg(long)]
        json: bool,
    },

    /// Run incremental inotify watcher updating index.bin atomically
    Watch,
}

#[derive(Serialize)]
struct IndexSummary {
    cache_path: String,
    entries: usize,
    watched_dirs: usize,
    generation: u64,
    elapsed_ms: u128,
}

fn canonicalize_or_abs(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    })
}

fn main() -> Result<()> {
    match run() {
        Ok(()) => Ok(()),
        Err(err)
            if err
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe) =>
        {
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let paths = ResolvedPaths::from_overrides(cli.config, cli.cache, cli.state);
    let cfg = Config::load(&paths.config_path)?;
    let home_ref = paths.home_dir.as_deref();

    match cli.command {
        Commands::Index {
            roots,
            no_stat,
            json,
        } => {
            let started = Instant::now();
            let scan_roots_vec = if roots.is_empty() {
                cfg.resolved_roots(home_ref)
            } else {
                roots.iter().map(|r| expand_tilde(r, home_ref)).collect()
            };
            let rules = ExclusionRules::from_config(&cfg);
            let res = scan_roots(
                &scan_roots_vec,
                &rules,
                &ScanOptions {
                    collect_stat: !no_stat,
                    ..Default::default()
                },
            );
            let fp = if roots.is_empty() {
                cfg.index_fingerprint(home_ref)
            } else {
                0
            };
            let generation = publish_index(&paths.cache_path, now_secs(), fp, &res.entries)?;

            if json {
                let summary = IndexSummary {
                    cache_path: paths.cache_path.to_string_lossy().into_owned(),
                    entries: res.entries.len(),
                    watched_dirs: res.watched_dirs.len(),
                    generation,
                    elapsed_ms: started.elapsed().as_millis(),
                };
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!(
                    "Indexed {} entries ({} dirs) in {}ms -> {}",
                    res.entries.len(),
                    res.watched_dirs.len(),
                    started.elapsed().as_millis(),
                    paths.cache_path.display()
                );
            }
        }

        Commands::Query {
            json,
            print0,
            limit,
            stat,
            live,
            no_refresh,
            roots,
            entry_type,
            query,
        } => {
            let now = now_secs();
            let state = StateStore::load(&paths.state_path);
            let query_str = query.join(" ");

            let expected_fp = cfg.index_fingerprint(home_ref);
            let entries = if live || !roots.is_empty() {
                let live_roots = if roots.is_empty() {
                    cfg.resolved_roots(home_ref)
                } else {
                    roots.iter().map(|r| expand_tilde(r, home_ref)).collect()
                };
                let rules = ExclusionRules::from_config(&cfg);
                scan_roots(&live_roots, &rules, &ScanOptions::default()).entries
            } else {
                let cached = if paths.cache_path.exists() {
                    read_index(&paths.cache_path).ok()
                } else {
                    None
                };

                match cached {
                    Some(idx) if idx.config_fingerprint == expected_fp => {
                        if !no_refresh
                            && searxh::index::is_stale(idx.built_at, cfg.index_ttl_sec, now)
                        {
                            let _ = spawn_background_refresh(
                                &paths.config_path,
                                &paths.cache_path,
                                &paths.state_path,
                            );
                        }
                        idx.entries
                    }
                    _ => {
                        let rules = ExclusionRules::from_config(&cfg);
                        let res = scan_roots(
                            &cfg.resolved_roots(home_ref),
                            &rules,
                            &ScanOptions::default(),
                        );
                        let _ = publish_index(&paths.cache_path, now, expected_fp, &res.entries);
                        res.entries
                    }
                }
            };

            let items = search(
                &entries,
                &state,
                &cfg,
                home_ref,
                &query_str,
                &QueryOptions {
                    limit,
                    with_stat: stat,
                    type_filter: entry_type.into(),
                    now,
                },
            );

            let stdout = io::stdout();
            let mut out = stdout.lock();
            if json {
                writeln!(out, "{}", serde_json::to_string_pretty(&items)?)?;
            } else if print0 {
                for item in &items {
                    match item {
                        QueryOutputItem::Entry(e) => write!(out, "{}\0", e.path)?,
                        QueryOutputItem::Virtual(v) => write!(out, "{}\0", v.name)?,
                    }
                }
            } else {
                for item in &items {
                    match item {
                        QueryOutputItem::Entry(e) => writeln!(out, "{}", e.path)?,
                        QueryOutputItem::Virtual(v) => writeln!(out, "{}\t{}", v.name, v.subtitle)?,
                    }
                }
            }
        }

        Commands::Inspect {
            json,
            max_bytes,
            max_lines,
            max_entries,
            gps,
            path,
        } => {
            let res = inspect_path(
                &path,
                &InspectOptions {
                    max_bytes,
                    max_lines,
                    max_entries,
                    include_gps: gps,
                },
            )
            .with_context(|| format!("inspect {}", path.display()))?;
            let stdout = io::stdout();
            let mut out = stdout.lock();
            if json {
                writeln!(out, "{}", serde_json::to_string_pretty(&res)?)?;
            } else {
                writeln!(
                    out,
                    "{} ({}, {}, {} bytes, {})",
                    res.path, res.preview_kind, res.category, res.size, res.mode
                )?;
                if let Some(img) = &res.image {
                    writeln!(
                        out,
                        "  image: {}x{} ({:?})",
                        img.width, img.height, img.format
                    )?;
                }
                if let Some(text) = &res.text {
                    writeln!(out, "---\n{text}")?;
                }
            }
        }

        Commands::Touch { path } => {
            let abs = canonicalize_or_abs(&path);
            let abs_str = abs.to_string_lossy().into_owned();
            let now = now_secs();
            let score =
                StateStore::update_locked(&paths.state_path, |state| state.touch(&abs_str, now))?;
            writeln!(io::stdout().lock(), "{:.3}", score)?;
        }

        Commands::Pin { path } => {
            let abs = canonicalize_or_abs(&path);
            let abs_str = abs.to_string_lossy().into_owned();
            StateStore::update_locked(&paths.state_path, |state| {
                state.pin(&abs_str);
            })?;
        }

        Commands::Unpin { path } => {
            let abs = canonicalize_or_abs(&path);
            let abs_str = abs.to_string_lossy().into_owned();
            StateStore::update_locked(&paths.state_path, |state| {
                state.unpin(&abs_str);
            })?;
        }

        Commands::Pins { json } => {
            let state = StateStore::load(&paths.state_path);
            let stdout = io::stdout();
            let mut out = stdout.lock();
            if json {
                writeln!(out, "{}", serde_json::to_string_pretty(&state.pinned)?)?;
            } else {
                for p in &state.pinned {
                    writeln!(out, "{p}")?;
                }
            }
        }

        Commands::Virtuals { json } => {
            let virtuals = cfg.merged_virtuals();
            let stdout = io::stdout();
            let mut out = stdout.lock();
            if json {
                writeln!(out, "{}", serde_json::to_string_pretty(&virtuals)?)?;
            } else {
                for (k, v) in &virtuals {
                    writeln!(out, "@{k}\t{}\t{}", v.label, v.description)?;
                }
            }
        }

        Commands::Watch => {
            run_watch(&cfg, &paths.cache_path, home_ref)?;
        }
    }

    Ok(())
}

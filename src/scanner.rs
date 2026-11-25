use crate::config::ExclusionRules;
use crate::index::{EntryKind, IndexEntry};
use jwalk::{Parallelism, WalkDirGeneric};
use std::collections::HashSet;
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub collect_stat: bool,
    pub max_depth: Option<usize>,
    pub threads: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            collect_stat: true,
            max_depth: None,
            threads: 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    pub entries: Vec<IndexEntry>,
    pub watched_dirs: Vec<PathBuf>,
}

pub fn mtime_secs(meta: &Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn entry_from_path(path: &Path, collect_stat: bool) -> Option<IndexEntry> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let ft = meta.file_type();
    let kind = if ft.is_dir() {
        EntryKind::Dir
    } else if ft.is_symlink() {
        EntryKind::Symlink
    } else {
        EntryKind::File
    };
    let (size, mtime) = if collect_stat {
        (meta.len(), mtime_secs(&meta))
    } else {
        (0, 0)
    };
    Some(IndexEntry {
        path: path.to_string_lossy().into_owned(),
        kind,
        size,
        mtime,
    })
}

pub fn scan_roots(roots: &[PathBuf], rules: &ExclusionRules, opts: &ScanOptions) -> ScanResult {
    let mut entries = Vec::new();
    let mut seen_paths = HashSet::new();
    let mut watched_dirs = Vec::new();
    let mut seen_dirs = HashSet::new();
    let shared_rules = Arc::new(rules.clone());

    for root in roots {
        if !root.exists() {
            continue;
        }
        let canon_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        if seen_dirs.insert(canon_root.clone()) {
            watched_dirs.push(canon_root.clone());
        }

        let parallelism = if opts.threads > 0 {
            Parallelism::RayonNewPool(opts.threads)
        } else {
            Parallelism::RayonDefaultPool {
                busy_timeout: std::time::Duration::from_secs(1),
            }
        };

        let walker_root = canon_root.clone();
        let rules_for_cb = Arc::clone(&shared_rules);
        let mut walker = WalkDirGeneric::<((), ())>::new(&canon_root)
            .skip_hidden(false)
            .follow_links(false)
            .parallelism(parallelism);

        if let Some(depth) = opts.max_depth {
            walker = walker.max_depth(depth);
        }

        walker = walker.process_read_dir(move |_depth, _dir_path, _state, children| {
            children.retain_mut(|child_res| {
                let Ok(entry) = child_res else {
                    return false;
                };
                let name = entry.file_name.to_string_lossy();
                let full_path = entry.path();
                let excluded = match full_path.strip_prefix(&walker_root) {
                    Ok(rel) => rules_for_cb.is_excluded_rel(&name, rel),
                    Err(_) => rules_for_cb.exclude_names.contains(name.as_ref()),
                };
                if excluded {
                    entry.read_children_path = None;
                    return false;
                }
                true
            });
        });

        for dir_entry_res in walker {
            let Ok(dir_entry) = dir_entry_res else {
                continue;
            };
            if dir_entry.depth == 0 {
                continue;
            }
            let path = dir_entry.path();
            let ft = dir_entry.file_type();
            let is_dir = ft.is_dir();
            if is_dir && seen_dirs.insert(path.clone()) {
                watched_dirs.push(path.clone());
            }

            let kind = if is_dir {
                EntryKind::Dir
            } else if ft.is_symlink() {
                EntryKind::Symlink
            } else {
                EntryKind::File
            };

            let path_str = path.to_string_lossy().into_owned();
            if !seen_paths.insert(path_str.clone()) {
                continue;
            }

            let (size, mtime) = if opts.collect_stat {
                match dir_entry.metadata() {
                    Ok(meta) => (meta.len(), mtime_secs(&meta)),
                    Err(_) => (0, 0),
                }
            } else {
                (0, 0)
            };

            entries.push(IndexEntry {
                path: path_str,
                kind,
                size,
                mtime,
            });
        }
    }

    ScanResult {
        entries,
        watched_dirs,
    }
}

use crate::config::{Config, ExclusionRules};
use crate::index::{EntryKind, IndexEntry, now_secs, write_index_atomic};
use crate::scanner::{ScanOptions, entry_from_path, scan_roots};
use anyhow::{Context, Result};
use notify::{
    Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub fn run_watch(cfg: &Config, cache_path: &Path, home_dir: Option<&Path>) -> Result<()> {
    let roots = cfg.resolved_roots(home_dir);
    let rules = ExclusionRules::from_config(cfg);
    let scan_opts = ScanOptions::default();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop);
    ctrlc::set_handler(move || {
        stop_handler.store(true, Ordering::SeqCst);
    })
    .context("install Ctrl-C/SIGTERM handler")?;

    let initial = scan_roots(&roots, &rules, &scan_opts);
    write_index_atomic(cache_path, now_secs(), &initial.entries)?;

    let mut entries_map: HashMap<String, IndexEntry> = initial
        .entries
        .into_iter()
        .map(|e| (e.path.clone(), e))
        .collect();
    let mut watched_dirs: HashSet<PathBuf> = HashSet::new();

    let (tx, rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.send(res);
        },
        NotifyConfig::default(),
    )
    .context("create inotify watcher")?;

    for dir in &initial.watched_dirs {
        if watcher.watch(dir, RecursiveMode::NonRecursive).is_ok() {
            watched_dirs.insert(dir.clone());
        }
    }

    let debounce = Duration::from_millis(cfg.watch_debounce_ms.max(100));
    let mut dirty_deadline: Option<Instant> = None;
    let mut needs_rescan = false;

    while !stop.load(Ordering::SeqCst) {
        let timeout = match dirty_deadline {
            Some(dl) => dl
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(200)),
            None => Duration::from_millis(250),
        };

        match rx.recv_timeout(timeout) {
            Ok(Ok(event)) => {
                if handle_event(
                    event,
                    &roots,
                    &rules,
                    &scan_opts,
                    &mut watcher,
                    &mut watched_dirs,
                    &mut entries_map,
                ) {
                    needs_rescan = true;
                }
                dirty_deadline = Some(Instant::now() + debounce);
            }
            Ok(Err(_)) => {
                needs_rescan = true;
                dirty_deadline = Some(Instant::now() + debounce);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if let Some(dl) = dirty_deadline
            && Instant::now() >= dl
        {
            if needs_rescan {
                let rescan = scan_roots(&roots, &rules, &scan_opts);
                entries_map = rescan
                    .entries
                    .into_iter()
                    .map(|e| (e.path.clone(), e))
                    .collect();
                for dir in &rescan.watched_dirs {
                    if !watched_dirs.contains(dir)
                        && watcher.watch(dir, RecursiveMode::NonRecursive).is_ok()
                    {
                        watched_dirs.insert(dir.clone());
                    }
                }
                needs_rescan = false;
            }
            let snapshot: Vec<IndexEntry> = entries_map.values().cloned().collect();
            let _ = write_index_atomic(cache_path, now_secs(), &snapshot);
            dirty_deadline = None;
        }
    }

    if dirty_deadline.is_some() {
        let snapshot: Vec<IndexEntry> = entries_map.values().cloned().collect();
        let _ = write_index_atomic(cache_path, now_secs(), &snapshot);
    }

    Ok(())
}

fn handle_event(
    event: Event,
    roots: &[PathBuf],
    rules: &ExclusionRules,
    scan_opts: &ScanOptions,
    watcher: &mut RecommendedWatcher,
    watched_dirs: &mut HashSet<PathBuf>,
    entries_map: &mut HashMap<String, IndexEntry>,
) -> bool {
    if matches!(event.kind, EventKind::Other) || event.need_rescan() {
        return true;
    }

    for path in event.paths {
        if rules.is_excluded_abs(&path, roots) {
            continue;
        }
        let path_str = path.to_string_lossy().into_owned();
        if path.exists() {
            if let Some(entry) = entry_from_path(&path, true) {
                let is_new_dir = entry.kind == EntryKind::Dir && !watched_dirs.contains(&path);
                entries_map.insert(path_str, entry);
                if is_new_dir {
                    let sub = scan_roots(std::slice::from_ref(&path), rules, scan_opts);
                    for sub_entry in sub.entries {
                        entries_map.insert(sub_entry.path.clone(), sub_entry);
                    }
                    for d in sub.watched_dirs {
                        if !watched_dirs.contains(&d)
                            && watcher.watch(&d, RecursiveMode::NonRecursive).is_ok()
                        {
                            watched_dirs.insert(d);
                        }
                    }
                }
            }
        } else {
            entries_map.remove(&path_str);
            let dir_prefix = format!("{}/", path_str.trim_end_matches('/'));
            entries_map.retain(|k, _| !k.starts_with(&dir_prefix));
            if watched_dirs.remove(&path) {
                let _ = watcher.unwatch(&path);
            }
        }
    }

    false
}

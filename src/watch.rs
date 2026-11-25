use crate::config::{Config, ExclusionRules};
use crate::index::{EntryKind, IndexEntry, WatcherLock, now_secs, publish_index};
use crate::scanner::{ScanOptions, entry_from_path, scan_roots};
use anyhow::{Context, Result, bail};
use notify::event::ModifyKind;
use notify::event::RenameMode;
use notify::{
    Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub fn run_watch(cfg: &Config, cache_path: &Path, home_dir: Option<&Path>) -> Result<()> {
    let Some(_watcher_guard) = WatcherLock::try_acquire(cache_path)? else {
        bail!(
            "another searxh watch instance already owns {}",
            cache_path.display()
        );
    };

    let raw_roots = cfg.resolved_roots(home_dir);
    let canon_roots: Vec<PathBuf> = raw_roots
        .into_iter()
        .map(|r| fs::canonicalize(&r).unwrap_or(r))
        .collect();
    let cfg_fingerprint = cfg.index_fingerprint(home_dir);
    let rules = ExclusionRules::from_config(cfg);
    let scan_opts = ScanOptions::default();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop);
    ctrlc::set_handler(move || {
        stop_handler.store(true, Ordering::SeqCst);
    })
    .context("install Ctrl-C/SIGTERM handler")?;

    let initial = scan_roots(&canon_roots, &rules, &scan_opts);
    publish_index(cache_path, now_secs(), cfg_fingerprint, &initial.entries)?;

    let mut entries_map: HashMap<String, IndexEntry> = initial
        .entries
        .into_iter()
        .map(|e| (e.path.clone(), e))
        .collect();
    let mut watched_dirs: HashSet<PathBuf> = HashSet::new();
    let mut warn_logged = false;

    let (tx, rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.send(res);
        },
        NotifyConfig::default(),
    )
    .context("create inotify watcher")?;

    for dir in &initial.watched_dirs {
        watch_dir_checked(&mut watcher, &mut watched_dirs, dir, &mut warn_logged);
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
                    &canon_roots,
                    &rules,
                    &scan_opts,
                    &mut watcher,
                    &mut watched_dirs,
                    &mut entries_map,
                    &mut warn_logged,
                ) {
                    needs_rescan = true;
                }
                dirty_deadline = Some(Instant::now() + debounce);
            }
            Ok(Err(err)) => {
                if !warn_logged {
                    eprintln!("searxh watch: notify error ({err}); scheduling rescan");
                    warn_logged = true;
                }
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
                let rescan = scan_roots(&canon_roots, &rules, &scan_opts);
                entries_map = rescan
                    .entries
                    .into_iter()
                    .map(|e| (e.path.clone(), e))
                    .collect();
                let next_dirs: HashSet<PathBuf> = rescan.watched_dirs.iter().cloned().collect();
                watched_dirs.retain(|d| {
                    if next_dirs.contains(d) {
                        true
                    } else {
                        let _ = watcher.unwatch(d);
                        false
                    }
                });
                for dir in &rescan.watched_dirs {
                    watch_dir_checked(&mut watcher, &mut watched_dirs, dir, &mut warn_logged);
                }
                needs_rescan = false;
            }
            let snapshot: Vec<IndexEntry> = entries_map.values().cloned().collect();
            let _ = publish_index(cache_path, now_secs(), cfg_fingerprint, &snapshot);
            dirty_deadline = None;
        }
    }

    if dirty_deadline.is_some() {
        let snapshot: Vec<IndexEntry> = entries_map.values().cloned().collect();
        let _ = publish_index(cache_path, now_secs(), cfg_fingerprint, &snapshot);
    }

    Ok(())
}

fn watch_dir_checked(
    watcher: &mut RecommendedWatcher,
    watched_dirs: &mut HashSet<PathBuf>,
    dir: &Path,
    warn_logged: &mut bool,
) {
    if watched_dirs.contains(dir) {
        return;
    }
    match watcher.watch(dir, RecursiveMode::NonRecursive) {
        Ok(()) => {
            watched_dirs.insert(dir.to_path_buf());
        }
        Err(err) => {
            if !*warn_logged {
                eprintln!(
                    "searxh watch: failed to watch {} ({err}); check fs.inotify.max_user_watches",
                    dir.display()
                );
                *warn_logged = true;
            }
        }
    }
}

fn remove_subtree(
    path: &Path,
    path_str: &str,
    watcher: &mut RecommendedWatcher,
    watched_dirs: &mut HashSet<PathBuf>,
    entries_map: &mut HashMap<String, IndexEntry>,
) {
    entries_map.remove(path_str);
    let dir_prefix = format!("{}/", path_str.trim_end_matches('/'));
    entries_map.retain(|k, _| !k.starts_with(&dir_prefix));

    watched_dirs.retain(|d| {
        if d == path || d.starts_with(path) {
            let _ = watcher.unwatch(d);
            false
        } else {
            true
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn handle_event(
    event: Event,
    roots: &[PathBuf],
    rules: &ExclusionRules,
    scan_opts: &ScanOptions,
    watcher: &mut RecommendedWatcher,
    watched_dirs: &mut HashSet<PathBuf>,
    entries_map: &mut HashMap<String, IndexEntry>,
    warn_logged: &mut bool,
) -> bool {
    if matches!(event.kind, EventKind::Other) || event.need_rescan() {
        return true;
    }

    let is_rename_or_create = matches!(
        event.kind,
        EventKind::Modify(ModifyKind::Name(_)) | EventKind::Create(_)
    );
    let is_rename_from = matches!(
        event.kind,
        EventKind::Modify(ModifyKind::Name(RenameMode::From))
    );

    for path in event.paths {
        let canon_path = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        let path_str = canon_path.to_string_lossy().into_owned();

        if is_rename_from || !canon_path.exists() {
            remove_subtree(&canon_path, &path_str, watcher, watched_dirs, entries_map);
            continue;
        }

        if rules.is_excluded_abs(&canon_path, roots) {
            remove_subtree(&canon_path, &path_str, watcher, watched_dirs, entries_map);
            continue;
        }

        if let Some(entry) = entry_from_path(&canon_path, true) {
            let is_dir = entry.kind == EntryKind::Dir;
            let unseen_dir = is_dir && !watched_dirs.contains(&canon_path);
            entries_map.insert(path_str, entry);

            if is_dir && (unseen_dir || is_rename_or_create) {
                let sub = scan_roots(std::slice::from_ref(&canon_path), rules, scan_opts);
                for sub_entry in sub.entries {
                    let sub_path = Path::new(&sub_entry.path);
                    if !rules.is_excluded_abs(sub_path, roots) {
                        entries_map.insert(sub_entry.path.clone(), sub_entry);
                    }
                }
                for d in sub.watched_dirs {
                    if !rules.is_excluded_abs(&d, roots) {
                        watch_dir_checked(watcher, watched_dirs, &d, warn_logged);
                    }
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use tempfile::TempDir;

    #[test]
    fn watch_rename_and_exclusion_parity() {
        let tmp = TempDir::new().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let dir_a = root.join("alpha");
        let dir_b = root.join("beta");
        let excluded_dir = root.join("proj/.git");
        fs::create_dir_all(&dir_a).unwrap();
        fs::create_dir_all(&excluded_dir).unwrap();
        fs::write(dir_a.join("keep.txt"), b"hi").unwrap();
        fs::write(excluded_dir.join("HEAD"), b"ref").unwrap();

        let cfg = Config {
            roots: vec![root.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let rules = ExclusionRules::from_config(&cfg);
        let scan_opts = ScanOptions::default();

        let (tx, _rx) = mpsc::channel();
        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            NotifyConfig::default(),
        )
        .unwrap();

        let scan = scan_roots(std::slice::from_ref(&root), &rules, &scan_opts);
        let mut entries_map: HashMap<String, IndexEntry> = scan
            .entries
            .into_iter()
            .map(|e| (e.path.clone(), e))
            .collect();
        let mut watched_dirs = HashSet::new();
        let mut warned = false;
        for d in &scan.watched_dirs {
            watch_dir_checked(&mut watcher, &mut watched_dirs, d, &mut warned);
        }

        // Rename alpha -> beta on disk and feed notify rename From/To events.
        fs::rename(&dir_a, &dir_b).unwrap();
        let from_ev = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::From)))
            .add_path(dir_a.clone());
        let to_ev =
            Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::To))).add_path(dir_b.clone());

        assert!(!handle_event(
            from_ev,
            std::slice::from_ref(&root),
            &rules,
            &scan_opts,
            &mut watcher,
            &mut watched_dirs,
            &mut entries_map,
            &mut warned,
        ));
        assert!(!handle_event(
            to_ev,
            std::slice::from_ref(&root),
            &rules,
            &scan_opts,
            &mut watcher,
            &mut watched_dirs,
            &mut entries_map,
            &mut warned,
        ));

        let old_file = dir_a.join("keep.txt").to_string_lossy().into_owned();
        let new_file = dir_b.join("keep.txt").to_string_lossy().into_owned();
        assert!(!entries_map.contains_key(&old_file));
        assert!(entries_map.contains_key(&new_file));
        assert!(!watched_dirs.contains(&dir_a));
        assert!(watched_dirs.contains(&dir_b));

        // Events inside excluded paths never enter entries_map.
        let excluded_ev = Event::new(EventKind::Create(notify::event::CreateKind::File))
            .add_path(excluded_dir.join("HEAD"));
        assert!(!handle_event(
            excluded_ev,
            std::slice::from_ref(&root),
            &rules,
            &scan_opts,
            &mut watcher,
            &mut watched_dirs,
            &mut entries_map,
            &mut warned,
        ));
        assert!(
            !entries_map
                .keys()
                .any(|k| k.contains("/.git/") || k.ends_with("/.git"))
        );
    }
}

use crate::config::{Config, ExclusionRules};
use crate::index::{
    EntryKind, IndexEntry, IndexWriteLock, WatcherLock, now_secs, publish_index,
    publish_index_locked,
};
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
use std::time::{Duration, Instant, SystemTime};

struct WatchRuntime {
    canon_roots: Vec<PathBuf>,
    rules: ExclusionRules,
    fingerprint: u64,
    debounce: Duration,
    max_publish: Duration,
}

fn max_publish_interval_for(debounce: Duration) -> Duration {
    let ms = (debounce.as_millis() as u64)
        .saturating_mul(10)
        .clamp(1_000, 10_000);
    Duration::from_millis(ms)
}

fn build_runtime(cfg: &Config, home_dir: Option<&Path>) -> WatchRuntime {
    let raw_roots = cfg.resolved_roots(home_dir);
    let canon_roots: Vec<PathBuf> = raw_roots
        .into_iter()
        .map(|r| fs::canonicalize(&r).unwrap_or(r))
        .collect();
    let debounce = Duration::from_millis(cfg.watch_debounce_ms.max(100));
    WatchRuntime {
        canon_roots,
        rules: ExclusionRules::from_config(cfg),
        fingerprint: cfg.index_fingerprint(home_dir),
        debounce,
        max_publish: max_publish_interval_for(debounce),
    }
}

fn config_stamp(cfg_path: &Path) -> Option<(Option<SystemTime>, u64)> {
    let meta = fs::metadata(cfg_path).ok()?;
    Some((meta.modified().ok(), meta.len()))
}

fn update_dirty_deadlines(
    now: Instant,
    debounce: Duration,
    max_publish: Duration,
    dirty_since: &mut Option<Instant>,
    dirty_deadline: &mut Option<Instant>,
) {
    let first = *dirty_since.get_or_insert(now);
    *dirty_deadline = Some((now + debounce).min(first + max_publish));
}

#[allow(clippy::too_many_arguments)]
fn rebuild_and_publish(
    cache_path: &Path,
    rt: &WatchRuntime,
    scan_opts: &ScanOptions,
    watcher: &mut RecommendedWatcher,
    watched_dirs: &mut HashSet<PathBuf>,
    entries_map: &mut HashMap<String, IndexEntry>,
    warn_logged: &mut bool,
) -> Result<()> {
    let _write_lock = IndexWriteLock::acquire(cache_path)?;
    let scan = scan_roots(&rt.canon_roots, &rt.rules, scan_opts);
    *entries_map = scan
        .entries
        .iter()
        .map(|e| (e.path.clone(), e.clone()))
        .collect();

    let next_dirs: HashSet<PathBuf> = scan.watched_dirs.iter().cloned().collect();
    watched_dirs.retain(|d| {
        if next_dirs.contains(d) {
            true
        } else {
            let _ = watcher.unwatch(d);
            false
        }
    });
    for dir in &scan.watched_dirs {
        watch_dir_checked(watcher, watched_dirs, dir, warn_logged);
    }

    publish_index_locked(cache_path, now_secs(), rt.fingerprint, &scan.entries)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn process_watch_result(
    res: std::result::Result<Event, notify::Error>,
    rt: &WatchRuntime,
    scan_opts: &ScanOptions,
    watcher: &mut RecommendedWatcher,
    watched_dirs: &mut HashSet<PathBuf>,
    entries_map: &mut HashMap<String, IndexEntry>,
    warn_logged: &mut bool,
    needs_rescan: &mut bool,
    dirty_since: &mut Option<Instant>,
    dirty_deadline: &mut Option<Instant>,
) {
    match res {
        Ok(event) => {
            if handle_event(
                event,
                &rt.canon_roots,
                &rt.rules,
                scan_opts,
                watcher,
                watched_dirs,
                entries_map,
                warn_logged,
            ) {
                *needs_rescan = true;
            }
            update_dirty_deadlines(
                Instant::now(),
                rt.debounce,
                rt.max_publish,
                dirty_since,
                dirty_deadline,
            );
        }
        Err(err) => {
            if !*warn_logged {
                eprintln!("searxh watch: notify error ({err}); scheduling rescan");
                *warn_logged = true;
            }
            *needs_rescan = true;
            update_dirty_deadlines(
                Instant::now(),
                rt.debounce,
                rt.max_publish,
                dirty_since,
                dirty_deadline,
            );
        }
    }
}

pub fn run_watch(
    cfg_path: &Path,
    cfg: &Config,
    cache_path: &Path,
    home_dir: Option<&Path>,
) -> Result<()> {
    let Some(_watcher_guard) = WatcherLock::try_acquire(cache_path)? else {
        bail!(
            "another searxh watch instance already owns {}",
            cache_path.display()
        );
    };

    let mut rt = build_runtime(cfg, home_dir);
    let scan_opts = ScanOptions::default();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop);
    ctrlc::set_handler(move || {
        stop_handler.store(true, Ordering::SeqCst);
    })
    .context("install Ctrl-C/SIGTERM handler")?;

    let mut entries_map: HashMap<String, IndexEntry> = HashMap::new();
    let mut watched_dirs: HashSet<PathBuf> = HashSet::new();
    let mut warn_logged = false;

    // Register inotify watches BEFORE the authoritative startup scan so filesystem
    // changes during initial traversal are captured and reconciled immediately.
    let (tx, rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.send(res);
        },
        NotifyConfig::default(),
    )
    .context("create inotify watcher")?;

    let pre_dirs = scan_roots(
        &rt.canon_roots,
        &rt.rules,
        &ScanOptions {
            collect_stat: false,
            ..Default::default()
        },
    );
    for dir in &pre_dirs.watched_dirs {
        watch_dir_checked(&mut watcher, &mut watched_dirs, dir, &mut warn_logged);
    }

    rebuild_and_publish(
        cache_path,
        &rt,
        &scan_opts,
        &mut watcher,
        &mut watched_dirs,
        &mut entries_map,
        &mut warn_logged,
    )?;

    let mut dirty_since: Option<Instant> = None;
    let mut dirty_deadline: Option<Instant> = None;
    let mut needs_rescan = false;
    let mut last_cfg_stamp = config_stamp(cfg_path);

    // Reconcile any events emitted while the authoritative startup scan ran.
    for pending in rx.try_iter() {
        process_watch_result(
            pending,
            &rt,
            &scan_opts,
            &mut watcher,
            &mut watched_dirs,
            &mut entries_map,
            &mut warn_logged,
            &mut needs_rescan,
            &mut dirty_since,
            &mut dirty_deadline,
        );
    }

    while !stop.load(Ordering::SeqCst) {
        let cur_stamp = config_stamp(cfg_path);
        if cur_stamp != last_cfg_stamp {
            last_cfg_stamp = cur_stamp;
            if let Ok(new_cfg) = Config::load(cfg_path) {
                let next_rt = build_runtime(&new_cfg, home_dir);
                if next_rt.fingerprint != rt.fingerprint {
                    rt = next_rt;
                    needs_rescan = false;
                    dirty_since = None;
                    dirty_deadline = None;
                    let _ = rebuild_and_publish(
                        cache_path,
                        &rt,
                        &scan_opts,
                        &mut watcher,
                        &mut watched_dirs,
                        &mut entries_map,
                        &mut warn_logged,
                    );
                } else {
                    rt = next_rt;
                }
            }
        }

        let timeout = match dirty_deadline {
            Some(dl) => dl
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(200)),
            None => Duration::from_millis(250),
        };

        match rx.recv_timeout(timeout) {
            Ok(first_res) => {
                process_watch_result(
                    first_res,
                    &rt,
                    &scan_opts,
                    &mut watcher,
                    &mut watched_dirs,
                    &mut entries_map,
                    &mut warn_logged,
                    &mut needs_rescan,
                    &mut dirty_since,
                    &mut dirty_deadline,
                );
                for extra in rx.try_iter().take(64) {
                    process_watch_result(
                        extra,
                        &rt,
                        &scan_opts,
                        &mut watcher,
                        &mut watched_dirs,
                        &mut entries_map,
                        &mut warn_logged,
                        &mut needs_rescan,
                        &mut dirty_since,
                        &mut dirty_deadline,
                    );
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if let Some(dl) = dirty_deadline
            && Instant::now() >= dl
        {
            if needs_rescan {
                let _ = rebuild_and_publish(
                    cache_path,
                    &rt,
                    &scan_opts,
                    &mut watcher,
                    &mut watched_dirs,
                    &mut entries_map,
                    &mut warn_logged,
                );
                needs_rescan = false;
            } else {
                let snapshot: Vec<IndexEntry> = entries_map.values().cloned().collect();
                let _ = publish_index(cache_path, now_secs(), rt.fingerprint, &snapshot);
            }
            dirty_deadline = None;
            dirty_since = None;
        }
    }

    if dirty_deadline.is_some() {
        let snapshot: Vec<IndexEntry> = entries_map.values().cloned().collect();
        let _ = publish_index(cache_path, now_secs(), rt.fingerprint, &snapshot);
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

    #[test]
    fn dirty_deadlines_respect_max_publish_interval() {
        let t0 = Instant::now();
        let debounce = Duration::from_millis(300);
        let max_publish = Duration::from_millis(1_000);
        let mut since = None;
        let mut deadline = None;

        update_dirty_deadlines(t0, debounce, max_publish, &mut since, &mut deadline);
        assert_eq!(since, Some(t0));
        assert_eq!(deadline, Some(t0 + debounce));

        // Rapid burst pushing past t0 + max_publish must clamp at t0 + max_publish.
        let t1 = t0 + Duration::from_millis(900);
        update_dirty_deadlines(t1, debounce, max_publish, &mut since, &mut deadline);
        assert_eq!(since, Some(t0));
        assert_eq!(deadline, Some(t0 + max_publish));
    }

    #[test]
    fn rebuild_updates_watches_and_config_reload_runtime() {
        let tmp = TempDir::new().unwrap();
        let root_a = fs::canonicalize(tmp.path()).unwrap().join("a");
        let root_b = fs::canonicalize(tmp.path()).unwrap().join("b");
        fs::create_dir_all(&root_a).unwrap();
        fs::create_dir_all(&root_b).unwrap();
        fs::write(root_a.join("a.txt"), b"a").unwrap();
        fs::write(root_b.join("b.txt"), b"b").unwrap();

        let cfg_path = tmp.path().join("config.toml");
        let cache_path = tmp.path().join("index.bin");
        fs::write(
            &cfg_path,
            format!("roots = [{:?}]\n", root_a.to_string_lossy()),
        )
        .unwrap();

        let (tx, _rx) = mpsc::channel();
        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            NotifyConfig::default(),
        )
        .unwrap();
        let mut watched_dirs = HashSet::new();
        let mut entries_map = HashMap::new();
        let mut warned = false;
        let scan_opts = ScanOptions::default();

        let cfg_a = Config::load(&cfg_path).unwrap();
        let rt_a = build_runtime(&cfg_a, None);
        let stamp_a = config_stamp(&cfg_path);
        rebuild_and_publish(
            &cache_path,
            &rt_a,
            &scan_opts,
            &mut watcher,
            &mut watched_dirs,
            &mut entries_map,
            &mut warned,
        )
        .unwrap();
        assert!(watched_dirs.contains(&root_a));
        assert!(!watched_dirs.contains(&root_b));
        assert_eq!(
            crate::index::read_index_header(&cache_path)
                .unwrap()
                .config_fingerprint,
            rt_a.fingerprint
        );

        // Mutate config.toml to switch root_a -> root_b.
        fs::write(
            &cfg_path,
            format!(
                "roots = [{:?}]\nwatch_debounce_ms = 250\n",
                root_b.to_string_lossy()
            ),
        )
        .unwrap();
        let stamp_b = config_stamp(&cfg_path);
        assert_ne!(stamp_a, stamp_b);
        let cfg_b = Config::load(&cfg_path).unwrap();
        let rt_b = build_runtime(&cfg_b, None);
        assert_ne!(rt_a.fingerprint, rt_b.fingerprint);
        rebuild_and_publish(
            &cache_path,
            &rt_b,
            &scan_opts,
            &mut watcher,
            &mut watched_dirs,
            &mut entries_map,
            &mut warned,
        )
        .unwrap();
        assert!(!watched_dirs.contains(&root_a));
        assert!(watched_dirs.contains(&root_b));
        assert_eq!(
            crate::index::read_index_header(&cache_path)
                .unwrap()
                .config_fingerprint,
            rt_b.fingerprint
        );
    }
}

use searxh::config::{Config, ExclusionRules, SortMode, VirtualFolderConfig};
use searxh::index::{
    EntryKind, IndexEntry, WatcherLock, is_watcher_active, publish_index, read_index,
    read_index_header, write_index_atomic,
};
use searxh::inspect::{InspectOptions, inspect_path};
use searxh::scanner::{ScanOptions, scan_roots};
use searxh::search::{QueryOptions, QueryOutputItem, TypeFilter, search};
use searxh::state::StateStore;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;

fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, bytes).unwrap();
}

/// Minimal valid 32x16 PNG (IHDR + IEND) sufficient for imagesize::size().
fn minimal_png_32x16() -> Vec<u8> {
    let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    // IHDR length = 13
    out.extend_from_slice(&13u32.to_be_bytes());
    out.extend_from_slice(b"IHDR");
    out.extend_from_slice(&32u32.to_be_bytes()); // width = 32
    out.extend_from_slice(&16u32.to_be_bytes()); // height = 16
    out.extend_from_slice(&[8, 2, 0, 0, 0]); // bit depth, color type, compression, filter, interlace
    out.extend_from_slice(&[0u8; 4]); // placeholder CRC (unused by header dimension reader)
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(b"IEND");
    out.extend_from_slice(&[0u8; 4]);
    out
}

/// Minimal JPEG with SOF0 64x48 and no EXIF, verifying graceful non-EXIF image parsing.
fn minimal_jpeg_64x48() -> Vec<u8> {
    vec![
        0xFF, 0xD8, // SOI
        0xFF, 0xC0, // SOF0
        0x00, 0x11, // length = 17
        0x08, // precision
        0x00, 0x30, // height = 48
        0x00, 0x40, // width = 64
        0x03, // components
        0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01, // component specs
        0xFF, 0xD9, // EOI
    ]
}

/// Build a valid JPEG containing an APP1 EXIF segment (Model="TestCam", ISO=400).
fn jpeg_with_synthetic_exif() -> Vec<u8> {
    // Little-endian TIFF header + IFD0 (Model + ExifIFDPointer) + ExifIFD (ISOSpeedRatings=400)
    let mut tiff = Vec::new();
    tiff.extend_from_slice(b"II"); // little endian
    tiff.extend_from_slice(&42u16.to_le_bytes());
    tiff.extend_from_slice(&8u32.to_le_bytes()); // IFD0 offset = 8

    // IFD0: 2 entries at offset 8 (2 + 2*12 + 4 = 30 bytes -> ends at 38)
    let model = b"TestCam\0";
    let model_offset = 38u32;
    let exif_ifd_offset = 38u32 + model.len() as u32;
    tiff.extend_from_slice(&2u16.to_le_bytes());
    // Tag 0x0110 Model (ASCII=2, count=8)
    tiff.extend_from_slice(&0x0110u16.to_le_bytes());
    tiff.extend_from_slice(&2u16.to_le_bytes());
    tiff.extend_from_slice(&(model.len() as u32).to_le_bytes());
    tiff.extend_from_slice(&model_offset.to_le_bytes());
    // Tag 0x8769 ExifIFDPointer (LONG=4, count=1)
    tiff.extend_from_slice(&0x8769u16.to_le_bytes());
    tiff.extend_from_slice(&4u16.to_le_bytes());
    tiff.extend_from_slice(&1u32.to_le_bytes());
    tiff.extend_from_slice(&exif_ifd_offset.to_le_bytes());
    tiff.extend_from_slice(&0u32.to_le_bytes()); // next IFD = 0

    tiff.extend_from_slice(model);
    // ExifIFD: 1 entry -> Tag 0x8827 PhotographicSensitivity (SHORT=3, count=1, val=400)
    tiff.extend_from_slice(&1u16.to_le_bytes());
    tiff.extend_from_slice(&0x8827u16.to_le_bytes());
    tiff.extend_from_slice(&3u16.to_le_bytes());
    tiff.extend_from_slice(&1u32.to_le_bytes());
    tiff.extend_from_slice(&400u16.to_le_bytes());
    tiff.extend_from_slice(&0u16.to_le_bytes());
    tiff.extend_from_slice(&0u32.to_le_bytes());

    let mut app1_payload = Vec::from(&b"Exif\0\0"[..]);
    app1_payload.extend_from_slice(&tiff);
    let app1_len = (app1_payload.len() + 2) as u16;

    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE1];
    jpeg.extend_from_slice(&app1_len.to_be_bytes());
    jpeg.extend_from_slice(&app1_payload);
    jpeg.extend_from_slice(&[
        0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00, 0x20, 0x00, 0x40, 0x03, 0x01, 0x11, 0x00, 0x02, 0x11,
        0x01, 0x03, 0x11, 0x01, 0xFF, 0xD9,
    ]);
    jpeg
}

#[test]
fn scanner_prunes_noise_while_keeping_config_and_normal_files() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();

    write_file(&root.join("Documents/notes.md"), b"# Notes");
    write_file(&root.join(".config/app.toml"), b"key = 1");
    write_file(&root.join(".zshrc"), b"export PATH=$PATH");
    write_file(&root.join(".git/HEAD"), b"ref: refs/heads/main");
    write_file(&root.join("proj/node_modules/pkg/index.js"), b"");
    write_file(&root.join(".local/share/Trash/deleted.txt"), b"trash");
    write_file(&root.join(".omp/wt/copy/foo.txt"), b"noise");

    let cfg = Config::default();
    let rules = ExclusionRules::from_config(&cfg);
    let scan = scan_roots(&[root.to_path_buf()], &rules, &ScanOptions::default());

    let paths: Vec<&str> = scan.entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.iter().any(|p| p.ends_with("Documents/notes.md")));
    assert!(paths.iter().any(|p| p.ends_with(".config/app.toml")));
    assert!(paths.iter().any(|p| p.ends_with(".zshrc")));

    assert!(!paths.iter().any(|p| p.contains(".git")));
    assert!(!paths.iter().any(|p| p.contains("node_modules")));
    assert!(!paths.iter().any(|p| p.contains(".local/share")));
    assert!(!paths.iter().any(|p| p.contains(".omp")));
}

#[test]
fn index_binary_roundtrip_atomic() {
    let tmp = TempDir::new().unwrap();
    let idx_path = tmp.path().join("cache/index.bin");
    let entries = vec![
        IndexEntry {
            path: "/home/u/Documents/report.pdf".to_string(),
            kind: EntryKind::File,
            size: 12345,
            mtime: 1_700_000_000,
        },
        IndexEntry {
            path: "/home/u/Documents".to_string(),
            kind: EntryKind::Dir,
            size: 4096,
            mtime: 1_700_000_123,
        },
    ];

    write_index_atomic(&idx_path, 1_700_000_999, &entries).unwrap();
    let loaded = read_index(&idx_path).unwrap();
    assert_eq!(loaded.built_at, 1_700_000_999);
    assert_eq!(loaded.entries, entries);
}

#[test]
fn ranking_fuzzy_frecency_pin_and_path_queries() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let now = 1_700_000_000;

    let entries = vec![
        IndexEntry {
            path: home
                .join("deep/sub/dir/my-config-backup.txt")
                .to_string_lossy()
                .into_owned(),
            kind: EntryKind::File,
            size: 10,
            mtime: now - 10_000,
        },
        IndexEntry {
            path: home
                .join("Documents/config.json")
                .to_string_lossy()
                .into_owned(),
            kind: EntryKind::File,
            size: 10,
            mtime: now - 10_000,
        },
        IndexEntry {
            path: home
                .join("Documents/LauncherFileProvider.qml")
                .to_string_lossy()
                .into_owned(),
            kind: EntryKind::File,
            size: 10,
            mtime: now - 500,
        },
        IndexEntry {
            path: home
                .join("projects/searxh/src/search.rs")
                .to_string_lossy()
                .into_owned(),
            kind: EntryKind::File,
            size: 10,
            mtime: now - 500,
        },
    ];

    let cfg = Config::default();
    let mut state = StateStore::default();
    let opts = QueryOptions {
        limit: 10,
        with_stat: false,
        type_filter: TypeFilter::All,
        now,
    };

    // Prefix/basename exactness beats deep substring match
    let res = search(&entries, &state, &cfg, Some(home), "config", &opts);
    let paths: Vec<String> = res
        .into_iter()
        .filter_map(|x| match x {
            QueryOutputItem::Entry(e) => Some(e.name),
            _ => None,
        })
        .collect();
    assert_eq!(paths[0], "config.json");

    // Fuzzy initialism ("lfp") finds LauncherFileProvider.qml
    let fuzzy = search(&entries, &state, &cfg, Some(home), "lfp", &opts);
    assert!(matches!(
        fuzzy.first(),
        Some(QueryOutputItem::Entry(e)) if e.name == "LauncherFileProvider.qml"
    ));

    // Path query with '/' matches relative path fragment
    let slash_res = search(&entries, &state, &cfg, Some(home), "searxh/search", &opts);
    assert!(matches!(
        slash_res.first(),
        Some(QueryOutputItem::Entry(e)) if e.name == "search.rs"
    ));

    // Touch boosts frecency; pin surfaces first on empty query
    let deep_path = home
        .join("deep/sub/dir/my-config-backup.txt")
        .to_string_lossy()
        .into_owned();
    state.touch(&deep_path, now);
    state.touch(&deep_path, now);
    state.pin(&deep_path);
    let empty_res = search(&entries, &state, &cfg, Some(home), "", &opts);
    assert!(matches!(
        empty_res.first(),
        Some(QueryOutputItem::Entry(e)) if e.pinned && e.path == deep_path
    ));
}

#[test]
fn virtual_folders_list_sort_and_scope() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let now = 1_700_000_000;

    let shots = home.join("Screenshots");
    let custom_dir = home.join("NotesVault");

    let entries = vec![
        IndexEntry {
            path: shots.join("older.png").to_string_lossy().into_owned(),
            kind: EntryKind::File,
            size: 100,
            mtime: now - 500,
        },
        IndexEntry {
            path: shots.join("newer.png").to_string_lossy().into_owned(),
            kind: EntryKind::File,
            size: 100,
            mtime: now - 10,
        },
        IndexEntry {
            path: custom_dir
                .join("alpha-todo.md")
                .to_string_lossy()
                .into_owned(),
            kind: EntryKind::File,
            size: 100,
            mtime: now - 50,
        },
        IndexEntry {
            path: home
                .join("Downloads/alpha-installer.tar.gz")
                .to_string_lossy()
                .into_owned(),
            kind: EntryKind::File,
            size: 100,
            mtime: now - 5,
        },
    ];

    let mut cfg = Config::default();
    cfg.virtuals.insert(
        "vault".to_string(),
        VirtualFolderConfig {
            label: "Vault".to_string(),
            roots: vec![custom_dir.to_string_lossy().into_owned()],
            sort: SortMode::Score,
            ..Default::default()
        },
    );
    let state = StateStore::default();
    let opts = QueryOptions {
        limit: 20,
        with_stat: false,
        type_filter: TypeFilter::All,
        now,
    };

    // "@" lists virtual folders
    let listed = search(&entries, &state, &cfg, Some(home), "@", &opts);
    assert!(
        listed
            .iter()
            .any(|x| matches!(x, QueryOutputItem::Virtual(v) if v.name == "@screenshots"))
    );
    assert!(
        listed
            .iter()
            .any(|x| matches!(x, QueryOutputItem::Virtual(v) if v.name == "@vault"))
    );

    // "@screenshots" sorts newest mtime first
    let shots_res = search(&entries, &state, &cfg, Some(home), "@screenshots", &opts);
    let shot_names: Vec<String> = shots_res
        .into_iter()
        .filter_map(|x| match x {
            QueryOutputItem::Entry(e) => Some(e.name),
            _ => None,
        })
        .collect();
    assert_eq!(shot_names, vec!["newer.png", "older.png"]);

    // "@vault alpha" scopes fuzzy search strictly to NotesVault
    let scoped = search(&entries, &state, &cfg, Some(home), "@vault alpha", &opts);
    assert_eq!(scoped.len(), 1);
    assert!(matches!(
        &scoped[0],
        QueryOutputItem::Entry(e) if e.name == "alpha-todo.md"
    ));
}

#[test]
fn inspect_text_utf8_binary_dir_and_images_with_exif() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    // 1. Extensionless shell script -> detected as text (not binary)
    let script_path = dir.join("setup");
    write_file(&script_path, b"#!/usr/bin/env bash\necho hello\n");
    let script_res = inspect_path(&script_path, &InspectOptions::default()).unwrap();
    assert_eq!(script_res.preview_kind, "text");
    assert!(script_res.text.unwrap().contains("#!/usr/bin/env bash"));

    // 2. Vietnamese multi-byte UTF-8 truncated across char boundary without panic
    let vn_path = dir.join("tieng_viet.txt");
    let vn_content = "Xin chào thế giới tiếng Việt ".repeat(10);
    write_file(&vn_path, vn_content.as_bytes());
    let vn_res = inspect_path(
        &vn_path,
        &InspectOptions {
            max_bytes: 17, // intentionally cuts inside multi-byte char
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(vn_res.preview_kind, "text");
    assert_eq!(vn_res.truncated, Some(true));
    assert!(!vn_res.text.unwrap().is_empty());

    // 3. Binary file containing NUL bytes
    let bin_path = dir.join("blob.dat");
    write_file(&bin_path, &[0x7F, b'E', b'L', b'F', 0x00, 0x01, 0x02]);
    let bin_res = inspect_path(&bin_path, &InspectOptions::default()).unwrap();
    assert_eq!(bin_res.preview_kind, "binary");

    // 4. Directory returns dirs before files sorted
    let folder = dir.join("folder");
    write_file(&folder.join("z_sub/inner.txt"), b"x");
    write_file(&folder.join("a_file.txt"), b"x");
    let dir_res = inspect_path(&folder, &InspectOptions::default()).unwrap();
    assert_eq!(dir_res.preview_kind, "dir");
    let entries = dir_res.entries.unwrap();
    assert_eq!(entries[0].kind, "dir");
    assert_eq!(entries[0].name, "z_sub");
    assert_eq!(entries[1].kind, "file");
    assert_eq!(entries[1].name, "a_file.txt");

    // 5. PNG dimensions
    let png_path = dir.join("pic.png");
    write_file(&png_path, &minimal_png_32x16());
    let png_res = inspect_path(&png_path, &InspectOptions::default()).unwrap();
    assert_eq!(png_res.preview_kind, "image");
    let png_img = png_res.image.unwrap();
    assert_eq!((png_img.width, png_img.height), (32, 16));
    assert_eq!(png_img.format.as_deref(), Some("png"));

    // 6. Minimal JPEG without EXIF
    let jpg_plain = dir.join("plain.jpg");
    write_file(&jpg_plain, &minimal_jpeg_64x48());
    let jpg_plain_res = inspect_path(&jpg_plain, &InspectOptions::default()).unwrap();
    let img_plain = jpg_plain_res.image.unwrap();
    assert_eq!((img_plain.width, img_plain.height), (64, 48));
    assert!(img_plain.exif.is_none());

    // 7. JPEG with synthetic EXIF (camera Model + ISO)
    let jpg_exif = dir.join("shot.jpg");
    write_file(&jpg_exif, &jpeg_with_synthetic_exif());
    let jpg_exif_res = inspect_path(&jpg_exif, &InspectOptions::default()).unwrap();
    let img_exif = jpg_exif_res.image.unwrap();
    let ex = img_exif.exif.unwrap();
    assert_eq!(ex.camera.as_deref(), Some("TestCam"));
    assert_eq!(ex.iso, Some(400));
}

#[test]
fn cli_end_to_end_index_query_touch_pin_inspect() {
    let tmp = TempDir::new().unwrap();
    let workspace = tmp.path().join("home");
    let cfg_path = tmp.path().join("config.toml");
    let cache_path = tmp.path().join("index.bin");
    let state_path = tmp.path().join("state.json");

    write_file(&workspace.join("Documents/roadmap.md"), b"# Roadmap");
    write_file(&workspace.join("Documents/readme.txt"), b"hello");
    write_file(
        &cfg_path,
        format!("roots = [{:?}]\n", workspace.to_string_lossy()).as_bytes(),
    );

    let bin = env!("CARGO_BIN_EXE_searxh");
    let base_args = [
        "--config",
        cfg_path.to_str().unwrap(),
        "--cache",
        cache_path.to_str().unwrap(),
        "--state",
        state_path.to_str().unwrap(),
    ];

    let idx_out = Command::new(bin)
        .args(base_args)
        .args(["index", "--json"])
        .output()
        .unwrap();
    assert!(idx_out.status.success(), "{:?}", idx_out);
    assert!(cache_path.exists());

    let roadmap = workspace.join("Documents/roadmap.md");
    assert!(
        Command::new(bin)
            .args(base_args)
            .args(["touch", "--", roadmap.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(bin)
            .args(base_args)
            .args(["pin", "--", roadmap.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );

    let query_out = Command::new(bin)
        .args(base_args)
        .args(["query", "--json", "--stat", "--no-refresh", "--", "road"])
        .output()
        .unwrap();
    assert!(query_out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&query_out.stdout).unwrap();
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr[0]["name"], "roadmap.md");
    assert_eq!(arr[0]["pinned"], true);
    assert!(arr[0]["mode"].as_str().unwrap().starts_with('-'));

    let inspect_out = Command::new(bin)
        .args(base_args)
        .args(["inspect", "--json", "--", roadmap.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(inspect_out.status.success());
    let ins_json: serde_json::Value = serde_json::from_slice(&inspect_out.stdout).unwrap();
    assert_eq!(ins_json["preview_kind"], "text");
    assert_eq!(ins_json["text"], "# Roadmap");
}

#[test]
fn v02_single_writer_generation_and_watcher_lock() {
    let tmp = TempDir::new().unwrap();
    let idx_path = Arc::new(tmp.path().join("cache/index.bin"));

    let mut handles = Vec::new();
    for worker in 0..8u64 {
        let path = Arc::clone(&idx_path);
        handles.push(thread::spawn(move || {
            let entry = vec![IndexEntry {
                path: format!("/tmp/file_{worker}.txt"),
                kind: EntryKind::File,
                size: worker,
                mtime: 1_700_000_000 + worker,
            }];
            publish_index(&path, 1_700_000_000 + worker, 42, &entry).unwrap()
        }));
    }

    let mut gens: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    gens.sort_unstable();
    assert_eq!(gens, vec![1, 2, 3, 4, 5, 6, 7, 8]);

    let hdr = read_index_header(&idx_path).unwrap();
    assert_eq!(hdr.generation, 8);
    assert_eq!(hdr.config_fingerprint, 42);
    let loaded = read_index(&idx_path).unwrap();
    assert_eq!(loaded.entries.len(), 1);

    // Watcher lock exclusivity
    assert!(!is_watcher_active(&idx_path));
    let guard = WatcherLock::try_acquire(&idx_path).unwrap().unwrap();
    assert!(is_watcher_active(&idx_path));
    assert!(WatcherLock::try_acquire(&idx_path).unwrap().is_none());
    drop(guard);
    assert!(!is_watcher_active(&idx_path));
    assert!(WatcherLock::try_acquire(&idx_path).unwrap().is_some());
}

#[test]
fn v02_concurrent_state_mutations_preserve_all_updates() {
    let tmp = TempDir::new().unwrap();
    let state_path = Arc::new(tmp.path().join("state.json"));

    let mut handles = Vec::new();
    for i in 0..16 {
        let p = Arc::clone(&state_path);
        handles.push(thread::spawn(move || {
            let target = format!("/home/u/doc_{i}.md");
            StateStore::update_locked(&p, |s| {
                s.touch(&target, 1_700_000_000);
                s.pin(&target);
            })
            .unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let final_state = StateStore::load(&state_path);
    assert_eq!(final_state.pinned.len(), 16);
    assert_eq!(final_state.frecency.len(), 16);
}

#[test]
fn v02_config_fingerprint_invalidation_cold_readiness_and_missing_stat_filter() {
    let tmp = TempDir::new().unwrap();
    let root_a = tmp.path().join("root_a");
    let root_b = tmp.path().join("root_b");
    let cfg_path = tmp.path().join("config.toml");
    let cache_path = tmp.path().join("index.bin");
    let state_path = tmp.path().join("state.json");

    write_file(&root_a.join("alpha.txt"), b"a1");
    write_file(&root_a.join("alpha_alive.txt"), b"a2");
    write_file(&root_b.join("beta.txt"), b"b1");

    // 1. Fingerprint sensitivity check
    let mut cfg1 = Config {
        roots: vec![root_a.to_string_lossy().into_owned()],
        ..Default::default()
    };
    let fp1 = cfg1.index_fingerprint(None);
    cfg1.index_ttl_sec = 9999; // ranking/lifecycle-only change must NOT invalidate
    cfg1.priority_roots.push("~/Extra".to_string());
    assert_eq!(cfg1.index_fingerprint(None), fp1);
    cfg1.exclude_names.push("secret_noise".to_string());
    assert_ne!(cfg1.index_fingerprint(None), fp1);

    // 2. Cold query with missing index.bin automatically builds V2 index
    write_file(
        &cfg_path,
        format!("roots = [{:?}]\n", root_a.to_string_lossy()).as_bytes(),
    );
    let bin = env!("CARGO_BIN_EXE_searxh");
    let base_args = [
        "--config",
        cfg_path.to_str().unwrap(),
        "--cache",
        cache_path.to_str().unwrap(),
        "--state",
        state_path.to_str().unwrap(),
    ];

    let cold_out = Command::new(bin)
        .args(base_args)
        .args(["query", "--json", "--stat", "--no-refresh", "--", "alpha"])
        .output()
        .unwrap();
    assert!(cold_out.status.success(), "{:?}", cold_out);
    assert!(cache_path.exists());
    let cold_arr: serde_json::Value = serde_json::from_slice(&cold_out.stdout).unwrap();
    assert_eq!(cold_arr.as_array().unwrap().len(), 2);

    // 3. Delete one file on disk without refreshing index.bin: `--stat` drops missing file
    //    and still fills Top-K (`--limit 1`) with the remaining live file.
    fs::remove_file(root_a.join("alpha.txt")).unwrap();
    let stat_out = Command::new(bin)
        .args(base_args)
        .args([
            "query",
            "--json",
            "--stat",
            "--no-refresh",
            "--limit",
            "1",
            "--",
            "alpha",
        ])
        .output()
        .unwrap();
    assert!(stat_out.status.success());
    let stat_arr: serde_json::Value = serde_json::from_slice(&stat_out.stdout).unwrap();
    let arr = stat_arr.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "alpha_alive.txt");

    // 4. Changing config roots invalidates stale index.bin automatically on next query
    write_file(
        &cfg_path,
        format!("roots = [{:?}]\n", root_b.to_string_lossy()).as_bytes(),
    );
    let invalidated_out = Command::new(bin)
        .args(base_args)
        .args(["query", "--json", "--no-refresh", "--", "beta"])
        .output()
        .unwrap();
    assert!(invalidated_out.status.success());
    let inv_arr: serde_json::Value = serde_json::from_slice(&invalidated_out.stdout).unwrap();
    let inv_items = inv_arr.as_array().unwrap();
    assert_eq!(inv_items.len(), 1);
    assert_eq!(inv_items[0]["name"], "beta.txt");
    assert_eq!(read_index_header(&cache_path).unwrap().generation, 2);
}

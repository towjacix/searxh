use searxh::config::Config;
use searxh::index::{EntryKind, IndexEntry, IndexSnapshot, publish_index};
use searxh::search::{QueryOptions, TypeFilter, search_snapshot};
use searxh::state::StateStore;
use std::path::Path;
use std::time::Instant;
use tempfile::TempDir;

fn synthetic_entries(home: &Path, count: usize) -> Vec<IndexEntry> {
    let prefixes = [
        "Documents/notes",
        "projects/searxh/src",
        "projects/linux-dots/dots/.config/quickshell/default/modules/views",
        "Downloads/archives",
        "Pictures/wallpapers/nature",
        ".config/hypr",
    ];
    let exts = ["rs", "qml", "md", "png", "toml", "json", "js", "ts"];
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let dir = prefixes[i % prefixes.len()];
        let ext = exts[i % exts.len()];
        let name = if i == count / 2 {
            "config.toml".to_string()
        } else if i == count / 3 {
            "LauncherFileProvider.qml".to_string()
        } else {
            format!("module_item_{}_{}.{}", i / 64, i, ext)
        };
        entries.push(IndexEntry {
            path: home
                .join(format!("{dir}/sub_{}/{name}", (i / 100) % 50))
                .to_string_lossy()
                .into_owned(),
            kind: if i % 17 == 0 {
                EntryKind::Dir
            } else {
                EntryKind::File
            },
            size: (i as u64) * 13 + 64,
            mtime: 1_700_000_000 + (i as u64 % 500_000),
        });
    }
    entries
}

fn main() {
    let count: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(150_000);

    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let cache_path = tmp.path().join("index.bin");
    let entries = synthetic_entries(&home, count);

    let t_write = Instant::now();
    publish_index(&cache_path, 1_700_500_000, 12345, &entries).unwrap();
    let write_ms = t_write.elapsed().as_secs_f64() * 1000.0;
    let file_kb = std::fs::metadata(&cache_path).unwrap().len() as f64 / 1024.0;

    let cfg = Config {
        roots: vec![home.to_string_lossy().into_owned()],
        ..Default::default()
    };
    let mut state = StateStore::default();
    for i in 0..20 {
        state.touch(&entries[i * 100].path, 1_700_500_000);
    }
    state.pin(&entries[0].path);

    let opts = QueryOptions {
        limit: 25,
        with_stat: false,
        type_filter: TypeFilter::All,
        now: 1_700_500_000,
    };

    // Warm pass + average over 5 runs for load + search queries
    let queries = [
        "config.toml",
        "lfp",
        "searxh/search",
        "module_item_120",
        "@screenshots",
        "",
    ];

    let mut load_ms_total = 0.0;
    let mut query_ms_total = vec![0.0; queries.len()];
    let iters = 5;

    for _ in 0..iters {
        let t_load = Instant::now();
        let snap = IndexSnapshot::open(&cache_path).unwrap();
        load_ms_total += t_load.elapsed().as_secs_f64() * 1000.0;

        for (qi, q) in queries.iter().enumerate() {
            let t_q = Instant::now();
            let res = search_snapshot(&snap, &state, &cfg, Some(&home), q, &opts);
            std::hint::black_box(res.len());
            query_ms_total[qi] += t_q.elapsed().as_secs_f64() * 1000.0;
        }
    }

    println!("entries={count} index_kb={file_kb:.1} write_ms={write_ms:.2}");
    println!("avg_load_ms={:.2}", load_ms_total / iters as f64);
    for (qi, q) in queries.iter().enumerate() {
        let label = if q.is_empty() { "<empty>" } else { q };
        println!(
            "avg_query_ms[{label}]={:.2}",
            query_ms_total[qi] / iters as f64
        );
    }
}

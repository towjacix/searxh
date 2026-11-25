use crate::config::{Config, SortMode, VirtualFolderConfig, expand_tilde, file_category};
use crate::index::{EntryKind, IndexEntry};
use crate::scanner::entry_from_path;
use crate::state::StateStore;
use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config as NucleoConfig, Matcher, Utf32Str};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeFilter {
    All,
    File,
    Dir,
}

#[derive(Debug, Clone)]
pub struct QueryOptions {
    pub limit: usize,
    pub with_stat: bool,
    pub type_filter: TypeFilter,
    pub now: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum QueryOutputItem {
    Entry(SearchResultItem),
    Virtual(VirtualListItem),
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchResultItem {
    pub path: String,
    pub name: String,
    pub kind: &'static str,
    pub category: &'static str,
    pub size: u64,
    pub mtime: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    pub score: i64,
    pub pinned: bool,
    pub frecency: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct VirtualListItem {
    pub kind: &'static str,
    pub name: String,
    pub title: String,
    pub subtitle: String,
    pub completion: String,
    pub count: usize,
}

pub enum ParsedQuery<'a> {
    Plain(&'a str),
    VirtualList { partial: &'a str },
    VirtualScoped { name: String, subquery: &'a str },
}

pub fn parse_virtual_query<'a>(
    raw: &'a str,
    virtuals: &BTreeMap<String, VirtualFolderConfig>,
) -> ParsedQuery<'a> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('@') {
        return ParsedQuery::Plain(trimmed);
    }
    let after_at = &trimmed[1..];
    if let Some((head, tail)) = after_at.split_once(char::is_whitespace) {
        let key = head.to_ascii_lowercase();
        if virtuals.contains_key(&key) {
            return ParsedQuery::VirtualScoped {
                name: key,
                subquery: tail.trim(),
            };
        }
        return ParsedQuery::VirtualList { partial: head };
    }
    let key = after_at.to_ascii_lowercase();
    if !key.is_empty() && virtuals.contains_key(&key) {
        return ParsedQuery::VirtualScoped {
            name: key,
            subquery: "",
        };
    }
    ParsedQuery::VirtualList { partial: after_at }
}

pub fn search(
    entries: &[IndexEntry],
    state: &StateStore,
    cfg: &Config,
    home_dir: Option<&Path>,
    raw_query: &str,
    opts: &QueryOptions,
) -> Vec<QueryOutputItem> {
    let virtuals = cfg.merged_virtuals();
    match parse_virtual_query(raw_query, &virtuals) {
        ParsedQuery::VirtualList { partial } => {
            list_matching_virtuals(entries, state, &virtuals, home_dir, partial, opts.limit)
                .into_iter()
                .map(QueryOutputItem::Virtual)
                .collect()
        }
        ParsedQuery::VirtualScoped { name, subquery } => {
            let Some(vcfg) = virtuals.get(&name) else {
                return Vec::new();
            };
            let vroots: Vec<PathBuf> = vcfg
                .roots
                .iter()
                .map(|r| expand_tilde(r, home_dir))
                .collect();
            let vexts: Vec<String> = vcfg
                .extensions
                .iter()
                .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
                .collect();
            let vcats: Vec<String> = vcfg
                .categories
                .iter()
                .map(|c| c.to_ascii_lowercase())
                .collect();

            let mut filtered: Vec<&IndexEntry> = entries
                .iter()
                .filter(|e| matches_type(e, opts.type_filter))
                .filter(|e| {
                    if vcfg.pinned_only && !state.is_pinned(&e.path) {
                        return false;
                    }
                    if vcfg.recent_only && state.frecency_score(&e.path, opts.now) <= 0.01 {
                        return false;
                    }
                    if !vroots.is_empty() {
                        let ep = Path::new(&e.path);
                        if !vroots.iter().any(|r| ep.starts_with(r)) {
                            return false;
                        }
                    }
                    if !vexts.is_empty() {
                        let ext = Path::new(&e.path)
                            .extension()
                            .and_then(|x| x.to_str())
                            .map(|x| x.to_ascii_lowercase())
                            .unwrap_or_default();
                        if !vexts.contains(&ext) {
                            return false;
                        }
                    }
                    if !vcats.is_empty() {
                        let cat = file_category(&e.path, e.kind == EntryKind::Dir);
                        if !vcats.iter().any(|c| c == cat) {
                            return false;
                        }
                    }
                    true
                })
                .collect();

            // Also include pinned/frecency paths not currently in index if pinned_only/recent_only
            let mut synthetic: Vec<IndexEntry> = Vec::new();
            if vcfg.pinned_only || vcfg.recent_only {
                let indexed: HashSet<&str> = entries.iter().map(|e| e.path.as_str()).collect();
                let candidates: Vec<&str> = if vcfg.pinned_only {
                    state.pinned.iter().map(|s| s.as_str()).collect()
                } else {
                    state.frecency.keys().map(|s| s.as_str()).collect()
                };
                for path_str in candidates {
                    if indexed.contains(path_str) {
                        continue;
                    }
                    if let Some(entry) = entry_from_path(Path::new(path_str), true)
                        && matches_type(&entry, opts.type_filter)
                    {
                        synthetic.push(entry);
                    }
                }
            }
            for s in &synthetic {
                filtered.push(s);
            }

            let items = if !subquery.is_empty() {
                rank_fuzzy(filtered.into_iter(), state, cfg, home_dir, subquery, opts)
            } else {
                rank_virtual_unfiltered(filtered, state, cfg, home_dir, vcfg.sort, opts)
            };
            items.into_iter().map(QueryOutputItem::Entry).collect()
        }
        ParsedQuery::Plain(q) => {
            if q.is_empty() {
                rank_empty_query(entries, state, opts)
                    .into_iter()
                    .map(QueryOutputItem::Entry)
                    .collect()
            } else {
                rank_fuzzy(
                    entries.iter().filter(|e| matches_type(e, opts.type_filter)),
                    state,
                    cfg,
                    home_dir,
                    q,
                    opts,
                )
                .into_iter()
                .map(QueryOutputItem::Entry)
                .collect()
            }
        }
    }
}

fn matches_type(entry: &IndexEntry, filter: TypeFilter) -> bool {
    match filter {
        TypeFilter::All => true,
        TypeFilter::File => entry.kind != EntryKind::Dir,
        TypeFilter::Dir => entry.kind == EntryKind::Dir,
    }
}

fn list_matching_virtuals(
    entries: &[IndexEntry],
    state: &StateStore,
    virtuals: &BTreeMap<String, VirtualFolderConfig>,
    home_dir: Option<&Path>,
    partial: &str,
    limit: usize,
) -> Vec<VirtualListItem> {
    let needle = partial.to_ascii_lowercase();
    let mut out = Vec::new();
    for (name, vcfg) in virtuals {
        if !needle.is_empty()
            && !name.contains(&needle)
            && !vcfg.label.to_ascii_lowercase().contains(&needle)
        {
            continue;
        }
        let count = count_virtual_matches(entries, state, vcfg, home_dir);
        let at_name = format!("@{name}");
        let desc = if vcfg.description.is_empty() {
            format!("{} items", count)
        } else {
            format!("{} ({} items)", vcfg.description, count)
        };
        out.push(VirtualListItem {
            kind: "virtual",
            name: at_name.clone(),
            title: if vcfg.label.is_empty() {
                at_name.clone()
            } else {
                format!("{} ({})", vcfg.label, at_name)
            },
            subtitle: desc,
            completion: format!("{at_name} "),
            count,
        });
    }
    out.sort_by(|a, b| {
        let ap = a.name[1..].starts_with(&needle);
        let bp = b.name[1..].starts_with(&needle);
        bp.cmp(&ap).then_with(|| a.name.cmp(&b.name))
    });
    out.truncate(limit);
    out
}

fn count_virtual_matches(
    entries: &[IndexEntry],
    state: &StateStore,
    vcfg: &VirtualFolderConfig,
    home_dir: Option<&Path>,
) -> usize {
    if vcfg.pinned_only {
        return state.pinned.len();
    }
    if vcfg.recent_only {
        return state.frecency.len();
    }
    let vroots: Vec<PathBuf> = vcfg
        .roots
        .iter()
        .map(|r| expand_tilde(r, home_dir))
        .collect();
    let vexts: Vec<String> = vcfg
        .extensions
        .iter()
        .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
        .collect();
    let vcats: Vec<String> = vcfg
        .categories
        .iter()
        .map(|c| c.to_ascii_lowercase())
        .collect();

    entries
        .iter()
        .filter(|e| {
            if !vroots.is_empty() {
                let ep = Path::new(&e.path);
                if !vroots.iter().any(|r| ep.starts_with(r)) {
                    return false;
                }
            }
            if !vexts.is_empty() {
                let ext = Path::new(&e.path)
                    .extension()
                    .and_then(|x| x.to_str())
                    .map(|x| x.to_ascii_lowercase())
                    .unwrap_or_default();
                if !vexts.contains(&ext) {
                    return false;
                }
            }
            if !vcats.is_empty() {
                let cat = file_category(&e.path, e.kind == EntryKind::Dir);
                if !vcats.iter().any(|c| c == cat) {
                    return false;
                }
            }
            true
        })
        .count()
}

fn rank_empty_query(
    entries: &[IndexEntry],
    state: &StateStore,
    opts: &QueryOptions,
) -> Vec<SearchResultItem> {
    let by_path: std::collections::HashMap<&str, &IndexEntry> =
        entries.iter().map(|e| (e.path.as_str(), e)).collect();

    let mut seen = HashSet::new();
    let mut ranked: Vec<(i64, u64, IndexEntry, f64, bool)> = Vec::new();

    for path_str in &state.pinned {
        if !seen.insert(path_str.clone()) {
            continue;
        }
        let entry = by_path
            .get(path_str.as_str())
            .map(|e| (*e).clone())
            .or_else(|| entry_from_path(Path::new(path_str), true));
        let Some(entry) = entry else { continue };
        if !matches_type(&entry, opts.type_filter) {
            continue;
        }
        let frec = state.frecency_score(path_str, opts.now);
        ranked.push((
            10_000 + (frec * 100.0) as i64,
            entry.mtime,
            entry,
            frec,
            true,
        ));
    }

    let mut frec_items: Vec<(&String, f64)> = state
        .frecency
        .keys()
        .map(|k| (k, state.frecency_score(k, opts.now)))
        .filter(|(_, s)| *s > 0.01)
        .collect();
    frec_items.sort_by(|a, b| b.1.total_cmp(&a.1));

    for (path_str, frec) in frec_items {
        if !seen.insert(path_str.clone()) {
            continue;
        }
        let entry = by_path
            .get(path_str.as_str())
            .map(|e| (*e).clone())
            .or_else(|| entry_from_path(Path::new(path_str), true));
        let Some(entry) = entry else { continue };
        if !matches_type(&entry, opts.type_filter) {
            continue;
        }
        ranked.push((
            1_000 + (frec * 200.0) as i64,
            entry.mtime,
            entry,
            frec,
            false,
        ));
    }

    // Backfill with recently modified files if still below limit
    if ranked.len() < opts.limit {
        let mut recent_disk: Vec<&IndexEntry> = entries
            .iter()
            .filter(|e| matches_type(e, opts.type_filter) && !seen.contains(&e.path))
            .collect();
        recent_disk.sort_by_key(|a| std::cmp::Reverse(a.mtime));
        for entry in recent_disk.into_iter().take(opts.limit - ranked.len()) {
            ranked.push((
                entry.mtime as i64 / 1_000_000,
                entry.mtime,
                entry.clone(),
                0.0,
                false,
            ));
        }
    }

    ranked.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.2.path.cmp(&b.2.path))
    });

    ranked
        .into_iter()
        .filter_map(|(score, _, entry, frec, pinned)| {
            finalize_item(entry, score, pinned, frec, opts.with_stat)
        })
        .take(opts.limit)
        .collect()
}

fn rank_virtual_unfiltered(
    entries: Vec<&IndexEntry>,
    state: &StateStore,
    cfg: &Config,
    home_dir: Option<&Path>,
    sort_mode: SortMode,
    opts: &QueryOptions,
) -> Vec<SearchResultItem> {
    let priority_roots = cfg.resolved_priority_roots(home_dir);
    let mut scored: Vec<(i64, u64, &IndexEntry, f64, bool)> = entries
        .into_iter()
        .map(|e| {
            let pinned = state.is_pinned(&e.path);
            let frec = state.frecency_score(&e.path, opts.now);
            let mut s = base_bias(e, pinned, frec, &priority_roots, home_dir, opts.now, false);
            if sort_mode == SortMode::Mtime {
                s = e.mtime as i64;
            }
            (s, e.mtime, e, frec, pinned)
        })
        .collect();

    match sort_mode {
        SortMode::Mtime => {
            scored.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.2.path.cmp(&b.2.path)))
        }
        SortMode::Name => scored.sort_by(|a, b| {
            basename(&a.2.path)
                .to_ascii_lowercase()
                .cmp(&basename(&b.2.path).to_ascii_lowercase())
                .then_with(|| a.2.path.cmp(&b.2.path))
        }),
        SortMode::Score => scored.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.2.path.cmp(&b.2.path))
        }),
    }
    scored
        .into_iter()
        .filter_map(|(score, _, entry, frec, pinned)| {
            finalize_item(entry.clone(), score, pinned, frec, opts.with_stat)
        })
        .take(opts.limit)
        .collect()
}

fn rank_fuzzy<'a>(
    entries: impl Iterator<Item = &'a IndexEntry>,
    state: &StateStore,
    cfg: &Config,
    home_dir: Option<&Path>,
    query: &str,
    opts: &QueryOptions,
) -> Vec<SearchResultItem> {
    let q_trimmed = query.trim();
    let q_lower = q_trimmed.to_ascii_lowercase();
    let has_slash = q_trimmed.contains('/');
    let allow_dotfile_bonus = q_trimmed.starts_with('.');
    let priority_roots = cfg.resolved_priority_roots(home_dir);

    let mut matcher = Matcher::new(NucleoConfig::DEFAULT.match_paths());
    let pat = Pattern::parse(q_trimmed, CaseMatching::Smart, Normalization::Smart);
    let mut utf32_buf = Vec::with_capacity(256);

    let mut scored: Vec<(i64, u64, &'a IndexEntry, f64, bool)> = Vec::new();

    for entry in entries {
        let name = basename(&entry.path);
        let match_score = if has_slash {
            let rel_or_full = strip_home_or_full(&entry.path, home_dir);
            pat.score(Utf32Str::new(rel_or_full, &mut utf32_buf), &mut matcher)
                .map(|s| s as i64)
        } else if let Some(s) = pat.score(Utf32Str::new(name, &mut utf32_buf), &mut matcher) {
            Some(s as i64 + 300)
        } else {
            let rel_or_full = strip_home_or_full(&entry.path, home_dir);
            pat.score(Utf32Str::new(rel_or_full, &mut utf32_buf), &mut matcher)
                .map(|s| (s as i64) / 2)
        };

        let Some(fuzzy_score) = match_score else {
            continue;
        };

        let name_lower = name.to_ascii_lowercase();
        let mut total = fuzzy_score;
        if name_lower == q_lower {
            total += 1200;
        } else if name_lower.starts_with(&q_lower) {
            total += 500;
        }

        let pinned = state.is_pinned(&entry.path);
        let frec = state.frecency_score(&entry.path, opts.now);
        total += base_bias(
            entry,
            pinned,
            frec,
            &priority_roots,
            home_dir,
            opts.now,
            allow_dotfile_bonus,
        );

        scored.push((total, entry.mtime, entry, frec, pinned));
    }

    scored.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.2.path.len().cmp(&b.2.path.len()))
            .then_with(|| a.2.path.cmp(&b.2.path))
    });

    scored
        .into_iter()
        .filter_map(|(score, _, entry, frec, pinned)| {
            finalize_item(entry.clone(), score, pinned, frec, opts.with_stat)
        })
        .take(opts.limit)
        .collect()
}

fn base_bias(
    entry: &IndexEntry,
    pinned: bool,
    frecency: f64,
    priority_roots: &[PathBuf],
    home_dir: Option<&Path>,
    now: u64,
    allow_dotfile: bool,
) -> i64 {
    let mut score = 0i64;
    if pinned {
        score += 400;
    }
    score += (frecency * 160.0).min(800.0) as i64;

    let ep = Path::new(&entry.path);
    if priority_roots.iter().any(|r| ep.starts_with(r)) {
        score += 120;
    }

    let age = now.saturating_sub(entry.mtime);
    if entry.mtime > 0 {
        if age <= 86_400 {
            score += 90;
        } else if age <= 7 * 86_400 {
            score += 45;
        } else if age <= 30 * 86_400 {
            score += 15;
        }
    }

    let name = basename(&entry.path);
    if !allow_dotfile && name.starts_with('.') {
        score -= 100;
    }

    let rel = strip_home_or_full(&entry.path, home_dir);
    let depth = rel.bytes().filter(|b| *b == b'/').count() as i64;
    score -= (depth * 12).min(120);

    score
}

fn finalize_item(
    mut entry: IndexEntry,
    score: i64,
    pinned: bool,
    frecency: f64,
    with_stat: bool,
) -> Option<SearchResultItem> {
    let mut mode_str = None;
    if with_stat {
        let meta = std::fs::symlink_metadata(&entry.path).ok()?;
        let ft = meta.file_type();
        entry.kind = if ft.is_dir() {
            EntryKind::Dir
        } else if ft.is_symlink() {
            EntryKind::Symlink
        } else {
            EntryKind::File
        };
        entry.size = meta.len();
        entry.mtime = crate::scanner::mtime_secs(&meta);
        mode_str = Some(format_unix_mode(meta.permissions().mode(), entry.kind));
    }

    let name = basename(&entry.path).to_string();
    let category = file_category(&entry.path, entry.kind == EntryKind::Dir);
    Some(SearchResultItem {
        path: entry.path,
        name,
        kind: entry.kind.as_str(),
        category,
        size: entry.size,
        mtime: entry.mtime,
        mode: mode_str,
        score,
        pinned,
        frecency,
    })
}

pub fn format_unix_mode(mode: u32, kind: EntryKind) -> String {
    let first = match kind {
        EntryKind::Dir => 'd',
        EntryKind::Symlink => 'l',
        EntryKind::File => '-',
    };
    let mut out = String::with_capacity(10);
    out.push(first);
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 0o7;
        out.push(if bits & 0o4 != 0 { 'r' } else { '-' });
        out.push(if bits & 0o2 != 0 { 'w' } else { '-' });
        out.push(if bits & 0o1 != 0 { 'x' } else { '-' });
    }
    out
}

pub fn basename(path: &str) -> &str {
    if path == "/" {
        return "/";
    }
    let clean = path.strip_suffix('/').unwrap_or(path);
    match clean.rfind('/') {
        Some(idx) => &clean[idx + 1..],
        None => clean,
    }
}

fn strip_home_or_full<'a>(path: &'a str, home_dir: Option<&Path>) -> &'a str {
    if let Some(home) = home_dir
        && let Some(home_str) = home.to_str()
        && let Some(rest) = path.strip_prefix(home_str)
    {
        return rest.strip_prefix('/').unwrap_or(rest);
    }
    path
}

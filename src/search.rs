use crate::config::{Config, SortMode, VirtualFolderConfig, expand_tilde, file_category};
use crate::index::{BorrowedEntry, EntryKind, IndexEntry, IndexSnapshot};
use crate::scanner::entry_from_path;
use crate::state::StateStore;
use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config as NucleoConfig, Matcher, Utf32Str};
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

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

/// Abstract read-only view over either an owned `Vec<IndexEntry>` slice or a
/// zero-copy `IndexSnapshot`, keeping every search path zero-allocation.
#[derive(Clone, Copy)]
pub enum EntrySource<'a> {
    Owned(&'a [IndexEntry]),
    Snapshot(&'a IndexSnapshot),
}

impl<'a> EntrySource<'a> {
    fn len(&self) -> usize {
        match self {
            Self::Owned(s) => s.len(),
            Self::Snapshot(s) => s.len(),
        }
    }

    fn iter(&self) -> EntrySourceIter<'a> {
        EntrySourceIter {
            source: *self,
            pos: 0,
        }
    }
}

#[derive(Clone)]
struct EntrySourceIter<'a> {
    source: EntrySource<'a>,
    pos: usize,
}

impl<'a> Iterator for EntrySourceIter<'a> {
    type Item = BorrowedEntry<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.pos;
        match &self.source {
            EntrySource::Owned(slice) => {
                let e = slice.get(idx)?;
                self.pos = idx + 1;
                Some(BorrowedEntry {
                    path: &e.path,
                    basename: basename(&e.path),
                    kind: e.kind,
                    size: e.size,
                    mtime: e.mtime,
                })
            }
            EntrySource::Snapshot(snap) => {
                if idx >= snap.len() {
                    return None;
                }
                self.pos = idx + 1;
                Some(snap.get(idx))
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.source.len().saturating_sub(self.pos);
        (rem, Some(rem))
    }
}

pub fn search(
    entries: &[IndexEntry],
    state: &StateStore,
    cfg: &Config,
    home_dir: Option<&Path>,
    raw_query: &str,
    opts: &QueryOptions,
) -> Vec<QueryOutputItem> {
    search_source(
        EntrySource::Owned(entries),
        state,
        cfg,
        home_dir,
        raw_query,
        opts,
    )
}

pub fn search_snapshot(
    snapshot: &IndexSnapshot,
    state: &StateStore,
    cfg: &Config,
    home_dir: Option<&Path>,
    raw_query: &str,
    opts: &QueryOptions,
) -> Vec<QueryOutputItem> {
    search_source(
        EntrySource::Snapshot(snapshot),
        state,
        cfg,
        home_dir,
        raw_query,
        opts,
    )
}

fn search_source(
    source: EntrySource<'_>,
    state: &StateStore,
    cfg: &Config,
    home_dir: Option<&Path>,
    raw_query: &str,
    opts: &QueryOptions,
) -> Vec<QueryOutputItem> {
    let virtuals = cfg.merged_virtuals();
    match parse_virtual_query(raw_query, &virtuals) {
        ParsedQuery::VirtualList { partial } => {
            list_matching_virtuals(&source, state, &virtuals, home_dir, partial, opts.limit)
                .into_iter()
                .map(QueryOutputItem::Virtual)
                .collect()
        }
        ParsedQuery::VirtualScoped { name, subquery } => {
            let Some(vcfg) = virtuals.get(&name) else {
                return Vec::new();
            };
            let vroots = normalize_root_strings(&vcfg.roots, home_dir);
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

            let mut filtered: Vec<BorrowedEntry<'_>> = source
                .iter()
                .filter(|e| matches_type_kind(e.kind, opts.type_filter))
                .filter(|e| {
                    matches_virtual_filters(*e, state, vcfg, &vroots, &vexts, &vcats, opts.now)
                })
                .collect();

            // Also include pinned/frecency paths not currently in index if pinned_only/recent_only
            let mut synthetic: Vec<IndexEntry> = Vec::new();
            if vcfg.pinned_only || vcfg.recent_only {
                let indexed: HashSet<&str> = filtered.iter().map(|e| e.path).collect();
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
                        && matches_type_kind(entry.kind, opts.type_filter)
                    {
                        synthetic.push(entry);
                    }
                }
            }
            for s in &synthetic {
                filtered.push(BorrowedEntry {
                    path: &s.path,
                    basename: basename(&s.path),
                    kind: s.kind,
                    size: s.size,
                    mtime: s.mtime,
                });
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
                rank_empty_query(&source, state, opts)
                    .into_iter()
                    .map(QueryOutputItem::Entry)
                    .collect()
            } else {
                rank_fuzzy(source.iter(), state, cfg, home_dir, q, opts)
                    .into_iter()
                    .map(QueryOutputItem::Entry)
                    .collect()
            }
        }
    }
}

#[inline]
fn matches_virtual_filters(
    e: BorrowedEntry<'_>,
    state: &StateStore,
    vcfg: &VirtualFolderConfig,
    vroots: &[String],
    vexts: &[String],
    vcats: &[String],
    now: u64,
) -> bool {
    if vcfg.pinned_only && !state.is_pinned(e.path) {
        return false;
    }
    if vcfg.recent_only && state.frecency_score(e.path, now) <= 0.01 {
        return false;
    }
    if !vroots.is_empty() && !vroots.iter().any(|r| path_starts_with_root(e.path, r)) {
        return false;
    }
    if !vexts.is_empty() {
        let Some((_, ext)) = e.basename.rsplit_once('.') else {
            return false;
        };
        if !vexts
            .iter()
            .any(|candidate| ext.eq_ignore_ascii_case(candidate))
        {
            return false;
        }
    }
    if !vcats.is_empty() {
        let cat = file_category(e.path, e.kind == EntryKind::Dir);
        if !vcats.iter().any(|c| c == cat) {
            return false;
        }
    }
    true
}

#[inline]
fn matches_type_kind(kind: EntryKind, filter: TypeFilter) -> bool {
    match filter {
        TypeFilter::All => true,
        TypeFilter::File => kind != EntryKind::Dir,
        TypeFilter::Dir => kind == EntryKind::Dir,
    }
}

fn normalize_root_strings(roots: &[String], home_dir: Option<&Path>) -> Vec<String> {
    roots
        .iter()
        .map(|r| {
            let p = expand_tilde(r, home_dir);
            let s = p.to_string_lossy();
            if s == "/" {
                "/".to_string()
            } else {
                s.trim_end_matches('/').to_string()
            }
        })
        .filter(|s| !s.is_empty())
        .collect()
}

#[inline]
fn path_starts_with_root(path: &str, root: &str) -> bool {
    if root == "/" {
        return path.starts_with('/');
    }
    if !path.starts_with(root) {
        return false;
    }
    path.len() == root.len() || path.as_bytes()[root.len()] == b'/'
}

fn list_matching_virtuals(
    source: &EntrySource<'_>,
    state: &StateStore,
    virtuals: &BTreeMap<String, VirtualFolderConfig>,
    home_dir: Option<&Path>,
    partial: &str,
    limit: usize,
) -> Vec<VirtualListItem> {
    let needle = partial.to_ascii_lowercase();
    struct PreparedVirtual<'a> {
        name: &'a String,
        vcfg: &'a VirtualFolderConfig,
        roots: Vec<String>,
        exts: Vec<String>,
        cats: Vec<String>,
        direct_count: Option<usize>,
    }

    let mut matched = Vec::new();
    for (name, vcfg) in virtuals {
        if !needle.is_empty()
            && !name.contains(&needle)
            && !vcfg.label.to_ascii_lowercase().contains(&needle)
        {
            continue;
        }
        let direct_count = if vcfg.pinned_only {
            Some(state.pinned.len())
        } else if vcfg.recent_only {
            Some(state.frecency.len())
        } else {
            None
        };
        matched.push(PreparedVirtual {
            name,
            vcfg,
            roots: normalize_root_strings(&vcfg.roots, home_dir),
            exts: vcfg
                .extensions
                .iter()
                .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
                .collect(),
            cats: vcfg
                .categories
                .iter()
                .map(|c| c.to_ascii_lowercase())
                .collect(),
            direct_count,
        });
    }

    let mut counts = vec![0usize; matched.len()];
    let need_scan = matched.iter().any(|m| m.direct_count.is_none());
    if need_scan {
        for e in source.iter() {
            for (idx, m) in matched.iter().enumerate() {
                if m.direct_count.is_none()
                    && matches_virtual_filters_static(e, &m.roots, &m.exts, &m.cats)
                {
                    counts[idx] += 1;
                }
            }
        }
    }

    let mut out = Vec::with_capacity(matched.len());
    for (idx, m) in matched.into_iter().enumerate() {
        let count = m.direct_count.unwrap_or(counts[idx]);
        let at_name = format!("@{}", m.name);
        let desc = if m.vcfg.description.is_empty() {
            format!("{count} items")
        } else {
            format!("{} ({count} items)", m.vcfg.description)
        };
        out.push(VirtualListItem {
            kind: "virtual",
            name: at_name.clone(),
            title: if m.vcfg.label.is_empty() {
                at_name.clone()
            } else {
                format!("{} ({at_name})", m.vcfg.label)
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

#[inline]
fn matches_virtual_filters_static(
    e: BorrowedEntry<'_>,
    vroots: &[String],
    vexts: &[String],
    vcats: &[String],
) -> bool {
    if !vroots.is_empty() && !vroots.iter().any(|r| path_starts_with_root(e.path, r)) {
        return false;
    }
    if !vexts.is_empty() {
        let Some((_, ext)) = e.basename.rsplit_once('.') else {
            return false;
        };
        if !vexts
            .iter()
            .any(|candidate| ext.eq_ignore_ascii_case(candidate))
        {
            return false;
        }
    }
    if !vcats.is_empty() {
        let cat = file_category(e.path, e.kind == EntryKind::Dir);
        if !vcats.iter().any(|c| c == cat) {
            return false;
        }
    }
    true
}

#[derive(Clone, Copy)]
struct RankedCandidate<'a> {
    tier: u8,
    score: i64,
    mtime: u64,
    entry: BorrowedEntry<'a>,
    frecency: f64,
    pinned: bool,
}

#[inline]
fn cmp_best_first(a: &RankedCandidate<'_>, b: &RankedCandidate<'_>) -> Ordering {
    b.tier
        .cmp(&a.tier)
        .then_with(|| b.score.cmp(&a.score))
        .then_with(|| b.mtime.cmp(&a.mtime))
        .then_with(|| a.entry.path.len().cmp(&b.entry.path.len()))
        .then_with(|| a.entry.path.cmp(b.entry.path))
}

struct WorstFirst<'a>(RankedCandidate<'a>);

impl PartialEq for WorstFirst<'_> {
    fn eq(&self, other: &Self) -> bool {
        cmp_best_first(&self.0, &other.0) == Ordering::Equal
    }
}

impl Eq for WorstFirst<'_> {}

impl PartialOrd for WorstFirst<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WorstFirst<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Put the weakest kept candidate at the max-heap root so `peek()`/`pop()`
        // evict the worst candidate in O(log K).
        cmp_best_first(&self.0, &other.0)
    }
}

#[inline]
fn heap_push_bounded<'a>(
    heap: &mut BinaryHeap<WorstFirst<'a>>,
    cap: usize,
    cand: RankedCandidate<'a>,
) {
    if cap == 0 {
        return;
    }
    if heap.len() < cap {
        heap.push(WorstFirst(cand));
    } else if let Some(worst) = heap.peek()
        && cmp_best_first(&cand, &worst.0) == Ordering::Less
    {
        heap.pop();
        heap.push(WorstFirst(cand));
    }
}

struct MtimeWorstFirst<'a>(BorrowedEntry<'a>);

impl PartialEq for MtimeWorstFirst<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.mtime == other.0.mtime && self.0.path == other.0.path
    }
}

impl Eq for MtimeWorstFirst<'_> {}

impl PartialOrd for MtimeWorstFirst<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MtimeWorstFirst<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .0
            .mtime
            .cmp(&self.0.mtime)
            .then_with(|| self.0.path.cmp(other.0.path))
    }
}

fn rank_empty_query(
    source: &EntrySource<'_>,
    state: &StateStore,
    opts: &QueryOptions,
) -> Vec<SearchResultItem> {
    if opts.limit == 0 {
        return Vec::new();
    }

    // Collect only the pinned + frecency keys (~tens/hundreds) instead of
    // building a HashMap over the entire 150k+ entry index.
    let mut wanted: HashSet<&str> =
        HashSet::with_capacity(state.pinned.len() + state.frecency.len());
    for p in &state.pinned {
        wanted.insert(p.as_str());
    }
    for k in state.frecency.keys() {
        wanted.insert(k.as_str());
    }

    let need_backfill = wanted.len() < opts.limit || opts.with_stat;
    let backfill_cap = if need_backfill {
        if opts.with_stat {
            opts.limit.saturating_mul(4).max(32)
        } else {
            opts.limit
        }
    } else {
        0
    };

    let mut matched_wanted: HashMap<&str, BorrowedEntry<'_>> = HashMap::with_capacity(wanted.len());
    let mut recent_heap: BinaryHeap<MtimeWorstFirst<'_>> = BinaryHeap::with_capacity(backfill_cap);

    for e in source.iter() {
        if !matches_type_kind(e.kind, opts.type_filter) {
            continue;
        }
        if wanted.contains(e.path) {
            matched_wanted.insert(e.path, e);
            continue;
        }
        if backfill_cap > 0 {
            if recent_heap.len() < backfill_cap {
                recent_heap.push(MtimeWorstFirst(e));
            } else if let Some(worst) = recent_heap.peek()
                && (e.mtime > worst.0.mtime || (e.mtime == worst.0.mtime && e.path < worst.0.path))
            {
                recent_heap.pop();
                recent_heap.push(MtimeWorstFirst(e));
            }
        }
    }

    let mut seen: HashSet<&str> = HashSet::with_capacity(wanted.len() + backfill_cap);
    let mut ranked: Vec<(i64, u64, IndexEntry, f64, bool)> = Vec::new();

    for path_str in &state.pinned {
        if !seen.insert(path_str.as_str()) {
            continue;
        }
        let entry = matched_wanted
            .get(path_str.as_str())
            .map(|e| e.to_owned_entry())
            .or_else(|| entry_from_path(Path::new(path_str), true));
        let Some(entry) = entry else { continue };
        if !matches_type_kind(entry.kind, opts.type_filter) {
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
        if !seen.insert(path_str.as_str()) {
            continue;
        }
        let entry = matched_wanted
            .get(path_str.as_str())
            .map(|e| e.to_owned_entry())
            .or_else(|| entry_from_path(Path::new(path_str), true));
        let Some(entry) = entry else { continue };
        if !matches_type_kind(entry.kind, opts.type_filter) {
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

    if ranked.len() < opts.limit || opts.with_stat {
        let mut recent_disk: Vec<BorrowedEntry<'_>> =
            recent_heap.into_iter().map(|x| x.0).collect();
        recent_disk.sort_by(|a, b| b.mtime.cmp(&a.mtime).then_with(|| a.path.cmp(b.path)));
        for entry in recent_disk {
            ranked.push((
                entry.mtime as i64 / 1_000_000,
                entry.mtime,
                entry.to_owned_entry(),
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
            finalize_borrowed(
                BorrowedEntry {
                    path: &entry.path,
                    basename: basename(&entry.path),
                    kind: entry.kind,
                    size: entry.size,
                    mtime: entry.mtime,
                },
                score,
                pinned,
                frec,
                opts.with_stat,
            )
        })
        .take(opts.limit)
        .collect()
}

fn rank_virtual_unfiltered(
    entries: Vec<BorrowedEntry<'_>>,
    state: &StateStore,
    cfg: &Config,
    home_dir: Option<&Path>,
    sort_mode: SortMode,
    opts: &QueryOptions,
) -> Vec<SearchResultItem> {
    if opts.limit == 0 {
        return Vec::new();
    }
    let priority_roots = normalize_root_strings(&cfg.priority_roots, home_dir);
    let mut scored: Vec<(i64, u64, BorrowedEntry<'_>, f64, bool)> = entries
        .into_iter()
        .map(|e| {
            let pinned = state.is_pinned(e.path);
            let frec = state.frecency_score(e.path, opts.now);
            let mut s = base_bias(e, pinned, frec, &priority_roots, home_dir, opts.now, false);
            if sort_mode == SortMode::Mtime {
                s = e.mtime as i64;
            }
            (s, e.mtime, e, frec, pinned)
        })
        .collect();

    match sort_mode {
        SortMode::Mtime => {
            scored.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.2.path.cmp(b.2.path)))
        }
        SortMode::Name => scored.sort_by(|a, b| {
            a.2.basename
                .to_ascii_lowercase()
                .cmp(&b.2.basename.to_ascii_lowercase())
                .then_with(|| a.2.path.cmp(b.2.path))
        }),
        SortMode::Score => scored.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.2.path.cmp(b.2.path))
        }),
    }
    scored
        .into_iter()
        .filter_map(|(score, _, entry, frec, pinned)| {
            finalize_borrowed(entry, score, pinned, frec, opts.with_stat)
        })
        .take(opts.limit)
        .collect()
}

#[inline]
fn eq_ignore_case(a: &str, q_trimmed: &str, q_ascii: bool, q_unicode_lower: Option<&str>) -> bool {
    if q_ascii {
        a.eq_ignore_ascii_case(q_trimmed)
    } else {
        a.to_lowercase() == q_unicode_lower.unwrap_or("")
    }
}

#[inline]
fn starts_with_ignore_case(
    haystack: &str,
    q_trimmed: &str,
    q_ascii: bool,
    q_unicode_lower: Option<&str>,
) -> bool {
    if q_ascii {
        let hb = haystack.as_bytes();
        let qb = q_trimmed.as_bytes();
        hb.len() >= qb.len() && hb[..qb.len()].eq_ignore_ascii_case(qb)
    } else {
        haystack
            .to_lowercase()
            .starts_with(q_unicode_lower.unwrap_or(""))
    }
}

fn collect_fuzzy_top_k<'a>(
    entries: impl Iterator<Item = BorrowedEntry<'a>>,
    state: &StateStore,
    priority_roots: &[String],
    home_dir: Option<&Path>,
    query: &str,
    opts: &QueryOptions,
    heap_cap: usize,
) -> (Vec<RankedCandidate<'a>>, usize) {
    let q_trimmed = query.trim();
    let q_ascii = q_trimmed.is_ascii();
    let q_unicode_lower = (!q_ascii).then(|| q_trimmed.to_lowercase());
    let has_slash = q_trimmed.contains('/');
    let allow_dotfile_bonus = q_trimmed.starts_with('.');

    let mut matcher = Matcher::new(NucleoConfig::DEFAULT.match_paths());
    let pat = Pattern::parse(q_trimmed, CaseMatching::Smart, Normalization::Smart);
    let mut utf32_buf = Vec::with_capacity(256);

    let mut heap: BinaryHeap<WorstFirst<'a>> = BinaryHeap::with_capacity(heap_cap);
    let mut matched_total = 0usize;

    for entry in entries {
        if !matches_type_kind(entry.kind, opts.type_filter) {
            continue;
        }
        let name = entry.basename;
        let (tier, fuzzy_score) = if has_slash {
            let rel_or_full = strip_home_or_full(entry.path, home_dir);
            let Some(s) = pat.score(Utf32Str::new(rel_or_full, &mut utf32_buf), &mut matcher)
            else {
                continue;
            };
            (1u8, s as i64)
        } else if let Some(s) = pat.score(Utf32Str::new(name, &mut utf32_buf), &mut matcher) {
            let tier = if eq_ignore_case(name, q_trimmed, q_ascii, q_unicode_lower.as_deref()) {
                3u8
            } else if starts_with_ignore_case(name, q_trimmed, q_ascii, q_unicode_lower.as_deref())
            {
                2u8
            } else {
                1u8
            };
            (tier, s as i64 + 300)
        } else {
            let rel_or_full = strip_home_or_full(entry.path, home_dir);
            let Some(s) = pat.score(Utf32Str::new(rel_or_full, &mut utf32_buf), &mut matcher)
            else {
                continue;
            };
            (0u8, (s as i64) / 2)
        };

        matched_total += 1;

        let pinned = state.is_pinned(entry.path);
        let frec = state.frecency_score(entry.path, opts.now);
        let tier_bonus: i64 = match tier {
            3 => 1200,
            2 => 500,
            _ => 0,
        };
        let total = fuzzy_score
            + tier_bonus
            + base_bias(
                entry,
                pinned,
                frec,
                priority_roots,
                home_dir,
                opts.now,
                allow_dotfile_bonus,
            );

        heap_push_bounded(
            &mut heap,
            heap_cap,
            RankedCandidate {
                tier,
                score: total,
                mtime: entry.mtime,
                entry,
                frecency: frec,
                pinned,
            },
        );
    }

    let mut out = Vec::with_capacity(heap.len());
    for item in heap.into_vec() {
        out.push(item.0);
    }
    out.sort_by(cmp_best_first);
    (out, matched_total)
}

fn rank_fuzzy<'a>(
    entries: impl Iterator<Item = BorrowedEntry<'a>> + Clone,
    state: &StateStore,
    cfg: &Config,
    home_dir: Option<&Path>,
    query: &str,
    opts: &QueryOptions,
) -> Vec<SearchResultItem> {
    if opts.limit == 0 {
        return Vec::new();
    }
    let priority_roots = normalize_root_strings(&cfg.priority_roots, home_dir);
    let initial_cap = if opts.with_stat {
        opts.limit.saturating_mul(4).max(32)
    } else {
        opts.limit
    };

    let (top, matched_total) = collect_fuzzy_top_k(
        entries.clone(),
        state,
        &priority_roots,
        home_dir,
        query,
        opts,
        initial_cap,
    );

    let mut results: Vec<SearchResultItem> = top
        .into_iter()
        .filter_map(|c| finalize_borrowed(c.entry, c.score, c.pinned, c.frecency, opts.with_stat))
        .take(opts.limit)
        .collect();

    // Rare backfill if more than `initial_cap - limit` top entries vanished from disk simultaneously.
    if opts.with_stat && results.len() < opts.limit && matched_total > initial_cap {
        let (all, _) = collect_fuzzy_top_k(
            entries,
            state,
            &priority_roots,
            home_dir,
            query,
            opts,
            matched_total,
        );
        results = all
            .into_iter()
            .filter_map(|c| {
                finalize_borrowed(c.entry, c.score, c.pinned, c.frecency, opts.with_stat)
            })
            .take(opts.limit)
            .collect();
    }

    results
}

#[inline]
fn base_bias(
    entry: BorrowedEntry<'_>,
    pinned: bool,
    frecency: f64,
    priority_roots: &[String],
    home_dir: Option<&Path>,
    now: u64,
    allow_dotfile: bool,
) -> i64 {
    let mut score = 0i64;
    if pinned {
        score += 400;
    }
    score += (frecency * 160.0).min(800.0) as i64;

    if priority_roots
        .iter()
        .any(|r| path_starts_with_root(entry.path, r))
    {
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

    if !allow_dotfile && entry.basename.starts_with('.') {
        score -= 100;
    }

    let rel = strip_home_or_full(entry.path, home_dir);
    let depth = rel.bytes().filter(|b| *b == b'/').count() as i64;
    score -= (depth * 12).min(120);

    score
}

fn finalize_borrowed(
    entry: BorrowedEntry<'_>,
    score: i64,
    pinned: bool,
    frecency: f64,
    with_stat: bool,
) -> Option<SearchResultItem> {
    let mut kind = entry.kind;
    let mut size = entry.size;
    let mut mtime = entry.mtime;
    let mut mode_str = None;
    if with_stat {
        let meta = std::fs::symlink_metadata(entry.path).ok()?;
        let ft = meta.file_type();
        kind = if ft.is_dir() {
            EntryKind::Dir
        } else if ft.is_symlink() {
            EntryKind::Symlink
        } else {
            EntryKind::File
        };
        size = meta.len();
        mtime = crate::scanner::mtime_secs(&meta);
        mode_str = Some(format_unix_mode(meta.permissions().mode(), kind));
    }

    let category = file_category(entry.path, kind == EntryKind::Dir);
    Some(SearchResultItem {
        path: entry.path.to_owned(),
        name: entry.basename.to_owned(),
        kind: kind.as_str(),
        category,
        size,
        mtime,
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

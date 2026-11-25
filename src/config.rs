use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortMode {
    #[default]
    Score,
    Mtime,
    Name,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct VirtualFolderConfig {
    pub label: String,
    pub description: String,
    pub roots: Vec<String>,
    pub extensions: Vec<String>,
    pub categories: Vec<String>,
    pub sort: SortMode,
    pub pinned_only: bool,
    pub recent_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub roots: Vec<String>,
    pub priority_roots: Vec<String>,
    pub exclude_names: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub include_hidden: bool,
    pub index_ttl_sec: u64,
    pub watch_debounce_ms: u64,
    pub inspect_max_bytes: usize,
    pub inspect_max_lines: usize,
    pub inspect_max_entries: usize,
    pub virtuals: BTreeMap<String, VirtualFolderConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            roots: vec!["$HOME".to_string()],
            priority_roots: vec![
                "~/Documents".to_string(),
                "~/projects".to_string(),
                "~/Downloads".to_string(),
                "~/Pictures".to_string(),
                "~/Screenshots".to_string(),
                "~/.config".to_string(),
            ],
            exclude_names: default_exclude_names(),
            exclude_paths: default_exclude_paths(),
            include_hidden: true,
            index_ttl_sec: 180,
            watch_debounce_ms: 800,
            inspect_max_bytes: 262_144,
            inspect_max_lines: 2000,
            inspect_max_entries: 40,
            virtuals: BTreeMap::new(),
        }
    }
}

pub fn default_exclude_names() -> Vec<String> {
    [
        ".git",
        "node_modules",
        ".cache",
        ".cargo",
        ".rustup",
        "target",
        "dist",
        "build",
        "__pycache__",
        ".tox",
        ".pytest_cache",
        ".mypy_cache",
        ".next",
        ".nuxt",
        ".venvs",
        ".venv",
        "venv",
        ".snapshots",
        ".generations",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

pub fn default_exclude_paths() -> Vec<String> {
    [
        ".local/share",
        ".local/state",
        ".omp",
        "go/pkg",
        "go/bin",
        ".zen",
        ".mozilla",
        ".steam",
        "Games",
        ".bun",
        ".npm",
        ".npm-global",
        ".arduino15",
        ".minecraft",
        ".nv",
        ".antigravity",
        ".gemini",
        ".codeium",
        ".claude-mem",
        ".cocoindex_code",
        ".android",
        ".java",
        ".gradle",
        ".pki",
        ".gnupg",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

pub fn default_virtuals() -> BTreeMap<String, VirtualFolderConfig> {
    let mut map = BTreeMap::new();
    map.insert(
        "pinned".to_string(),
        VirtualFolderConfig {
            label: "Pinned".to_string(),
            description: "Pinned favorite files and folders".to_string(),
            pinned_only: true,
            sort: SortMode::Score,
            ..Default::default()
        },
    );
    map.insert(
        "recent".to_string(),
        VirtualFolderConfig {
            label: "Recent".to_string(),
            description: "Frequently and recently opened files".to_string(),
            recent_only: true,
            sort: SortMode::Score,
            ..Default::default()
        },
    );
    map.insert(
        "modified".to_string(),
        VirtualFolderConfig {
            label: "Recently Modified".to_string(),
            description: "Newest modified files across indexed roots".to_string(),
            sort: SortMode::Mtime,
            ..Default::default()
        },
    );
    map.insert(
        "images".to_string(),
        VirtualFolderConfig {
            label: "Images".to_string(),
            description: "Photos, screenshots, and artwork".to_string(),
            categories: vec!["image".to_string()],
            sort: SortMode::Mtime,
            ..Default::default()
        },
    );
    map.insert(
        "docs".to_string(),
        VirtualFolderConfig {
            label: "Documents".to_string(),
            description: "PDFs, notes, spreadsheets, and text documents".to_string(),
            categories: vec!["document".to_string()],
            sort: SortMode::Mtime,
            ..Default::default()
        },
    );
    map.insert(
        "videos".to_string(),
        VirtualFolderConfig {
            label: "Videos".to_string(),
            description: "Video clips and recordings".to_string(),
            categories: vec!["video".to_string()],
            sort: SortMode::Mtime,
            ..Default::default()
        },
    );
    map.insert(
        "audio".to_string(),
        VirtualFolderConfig {
            label: "Audio".to_string(),
            description: "Music and audio recordings".to_string(),
            categories: vec!["audio".to_string()],
            sort: SortMode::Score,
            ..Default::default()
        },
    );
    map.insert(
        "screenshots".to_string(),
        VirtualFolderConfig {
            label: "Screenshots".to_string(),
            description: "Recent screenshots".to_string(),
            roots: vec![
                "~/Screenshots".to_string(),
                "~/Pictures/Screenshots".to_string(),
            ],
            extensions: vec!["png".to_string(), "jpg".to_string(), "webp".to_string()],
            sort: SortMode::Mtime,
            ..Default::default()
        },
    );
    map.insert(
        "downloads".to_string(),
        VirtualFolderConfig {
            label: "Downloads".to_string(),
            description: "Files in ~/Downloads".to_string(),
            roots: vec!["~/Downloads".to_string()],
            sort: SortMode::Mtime,
            ..Default::default()
        },
    );
    map
}

#[derive(Debug, Clone)]
pub struct ResolvedPaths {
    pub home_dir: Option<PathBuf>,
    pub config_path: PathBuf,
    pub cache_path: PathBuf,
    pub state_path: PathBuf,
}

impl ResolvedPaths {
    pub fn from_overrides(
        config_override: Option<PathBuf>,
        cache_override: Option<PathBuf>,
        state_override: Option<PathBuf>,
    ) -> Self {
        let home_dir = std::env::var_os("HOME").map(PathBuf::from);
        let config_base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| home_dir.as_ref().map(|h| h.join(".config")))
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let cache_base = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| home_dir.as_ref().map(|h| h.join(".cache")))
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let state_base = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| home_dir.as_ref().map(|h| h.join(".local/state")))
            .unwrap_or_else(|| PathBuf::from("/tmp"));

        Self {
            home_dir,
            config_path: config_override
                .unwrap_or_else(|| config_base.join("searxh").join("config.toml")),
            cache_path: cache_override
                .unwrap_or_else(|| cache_base.join("searxh").join("index.bin")),
            state_path: state_override
                .unwrap_or_else(|| state_base.join("searxh").join("state.json")),
        }
    }
}

pub fn expand_tilde(raw: &str, home_dir: Option<&Path>) -> PathBuf {
    let trimmed = raw.trim();
    if let Some(home) = home_dir {
        if trimmed == "~" || trimmed == "$HOME" {
            return home.to_path_buf();
        }
        if let Some(rest) = trimmed.strip_prefix("~/") {
            return home.join(rest);
        }
        if let Some(rest) = trimmed.strip_prefix("$HOME/") {
            return home.join(rest);
        }
    }
    PathBuf::from(trimmed)
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct RawConfigFile {
    roots: Option<Vec<String>>,
    priority_roots: Option<Vec<String>>,
    exclude_names: Option<Vec<String>>,
    exclude_paths: Option<Vec<String>>,
    include_hidden: Option<bool>,
    index_ttl_sec: Option<u64>,
    watch_debounce_ms: Option<u64>,
    inspect_max_bytes: Option<usize>,
    inspect_max_lines: Option<usize>,
    inspect_max_entries: Option<usize>,
    #[serde(rename = "virtual")]
    virtual_table: Option<BTreeMap<String, VirtualFolderConfig>>,
    virtuals: Option<BTreeMap<String, VirtualFolderConfig>>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let mut cfg = Config::default();
        if !path.exists() {
            return Ok(cfg);
        }
        let raw_text = fs::read_to_string(path)?;
        let raw: RawConfigFile = toml::from_str(&raw_text)?;
        if let Some(roots) = raw.roots {
            cfg.roots = roots;
        }
        if let Some(priority_roots) = raw.priority_roots {
            cfg.priority_roots = priority_roots;
        }
        if let Some(exclude_names) = raw.exclude_names {
            cfg.exclude_names = exclude_names;
        }
        if let Some(exclude_paths) = raw.exclude_paths {
            cfg.exclude_paths = exclude_paths;
        }
        if let Some(include_hidden) = raw.include_hidden {
            cfg.include_hidden = include_hidden;
        }
        if let Some(ttl) = raw.index_ttl_sec {
            cfg.index_ttl_sec = ttl;
        }
        if let Some(debounce) = raw.watch_debounce_ms {
            cfg.watch_debounce_ms = debounce;
        }
        if let Some(bytes) = raw.inspect_max_bytes {
            cfg.inspect_max_bytes = bytes;
        }
        if let Some(lines) = raw.inspect_max_lines {
            cfg.inspect_max_lines = lines;
        }
        if let Some(entries) = raw.inspect_max_entries {
            cfg.inspect_max_entries = entries;
        }
        if let Some(vt) = raw.virtual_table {
            cfg.virtuals.extend(vt);
        }
        if let Some(vs) = raw.virtuals {
            cfg.virtuals.extend(vs);
        }
        Ok(cfg)
    }

    pub fn resolved_roots(&self, home_dir: Option<&Path>) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for r in &self.roots {
            let p = expand_tilde(r, home_dir);
            if !p.as_os_str().is_empty() && !out.contains(&p) {
                out.push(p);
            }
        }
        if out.is_empty()
            && let Some(home) = home_dir
        {
            out.push(home.to_path_buf());
        }
        out
    }

    pub fn resolved_priority_roots(&self, home_dir: Option<&Path>) -> Vec<PathBuf> {
        self.priority_roots
            .iter()
            .map(|r| expand_tilde(r, home_dir))
            .collect()
    }

    pub fn merged_virtuals(&self) -> BTreeMap<String, VirtualFolderConfig> {
        let mut merged = default_virtuals();
        for (k, v) in &self.virtuals {
            let key = k.trim().trim_start_matches('@').to_lowercase();
            if key.is_empty() {
                continue;
            }
            let mut item = v.clone();
            if item.label.is_empty() {
                item.label = key.clone();
            }
            merged.insert(key, item);
        }
        merged
    }

    /// Deterministic FNV-1a 64-bit fingerprint over config knobs that affect the
    /// indexed entry set (`roots`, `exclude_names`, `exclude_paths`, `include_hidden`).
    /// Ranking-only fields (priority_roots, virtuals, TTL, debounce) are excluded
    /// so tweaking sort/UI settings never invalidates the binary index.
    pub fn index_fingerprint(&self, home_dir: Option<&Path>) -> u64 {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0100_0000_01b3;

        #[inline]
        fn mix_bytes(h: &mut u64, bytes: &[u8]) {
            for &b in bytes {
                *h ^= u64::from(b);
                *h = h.wrapping_mul(FNV_PRIME);
            }
            *h ^= 0xff;
            *h = h.wrapping_mul(FNV_PRIME);
        }

        let mut h = FNV_OFFSET;
        mix_bytes(&mut h, b"roots");
        for root in self.resolved_roots(home_dir) {
            let canon = fs::canonicalize(&root).unwrap_or(root);
            mix_bytes(&mut h, canon.to_string_lossy().as_bytes());
        }

        mix_bytes(&mut h, b"exclude_names");
        let mut names: Vec<&str> = self.exclude_names.iter().map(|s| s.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        for name in names {
            mix_bytes(&mut h, name.as_bytes());
        }

        mix_bytes(&mut h, b"exclude_paths");
        let mut paths: Vec<&str> = self
            .exclude_paths
            .iter()
            .map(|s| s.trim_matches('/'))
            .filter(|s| !s.is_empty())
            .collect();
        paths.sort_unstable();
        paths.dedup();
        for p in paths {
            mix_bytes(&mut h, p.as_bytes());
        }

        mix_bytes(&mut h, b"include_hidden");
        mix_bytes(&mut h, &[u8::from(self.include_hidden)]);
        h
    }
}

#[derive(Debug, Clone)]
pub struct ExclusionRules {
    pub exclude_names: HashSet<String>,
    pub exclude_paths: Vec<PathBuf>,
    pub include_hidden: bool,
}

impl ExclusionRules {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            exclude_names: cfg.exclude_names.iter().cloned().collect(),
            exclude_paths: cfg
                .exclude_paths
                .iter()
                .map(|p| PathBuf::from(p.trim_matches('/')))
                .filter(|p| !p.as_os_str().is_empty())
                .collect(),
            include_hidden: cfg.include_hidden,
        }
    }

    pub fn is_excluded_rel(&self, name: &str, rel_path: &Path) -> bool {
        if !self.include_hidden && name.starts_with('.') && name != "." && name != ".." {
            return true;
        }
        if self.exclude_names.contains(name) {
            return true;
        }
        for prefix in &self.exclude_paths {
            if rel_path.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    pub fn is_excluded_abs(&self, full_path: &Path, roots: &[PathBuf]) -> bool {
        let name = full_path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        if name.is_empty() {
            return false;
        }
        for root in roots {
            if let Ok(rel) = full_path.strip_prefix(root) {
                if rel.as_os_str().is_empty() {
                    return false;
                }
                for comp in rel.components() {
                    let s = comp.as_os_str().to_string_lossy();
                    if self.exclude_names.contains(s.as_ref()) {
                        return true;
                    }
                    if !self.include_hidden && s.starts_with('.') {
                        return true;
                    }
                }
                for prefix in &self.exclude_paths {
                    if rel.starts_with(prefix) {
                        return true;
                    }
                }
                return false;
            }
        }
        self.exclude_names.contains(name.as_ref())
    }
}

pub fn file_category(path: &str, is_dir: bool) -> &'static str {
    if is_dir || path.ends_with('/') {
        return "directory";
    }
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some(
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "bmp" | "ico" | "avif" | "tiff"
            | "tif" | "heic" | "heif" | "jxl",
        ) => "image",
        Some("mp4" | "mkv" | "webm" | "avi" | "mov" | "flv" | "m4v" | "wmv") => "video",
        Some("mp3" | "flac" | "wav" | "ogg" | "m4a" | "aac" | "opus" | "wma") => "audio",
        Some(
            "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "txt" | "md" | "rst" | "csv"
            | "odt" | "ods" | "odp",
        ) => "document",
        Some("zip" | "tar" | "gz" | "tgz" | "bz2" | "xz" | "zst" | "7z" | "rar") => "archive",
        Some("desktop" | "sh" | "bin" | "exe" | "appimage") => "application",
        _ => "other",
    }
}

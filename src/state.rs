use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

const HALF_LIFE_SECS: f64 = 7.0 * 86_400.0;
const MAX_FRECENCY_RECORDS: usize = 5000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrecencyRecord {
    pub score: f64,
    pub last_accessed: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StateStore {
    pub frecency: HashMap<String, FrecencyRecord>,
    pub pinned: Vec<String>,
}

impl StateStore {
    pub fn load(path: &Path) -> Self {
        let Ok(file) = File::open(path) else {
            return Self::default();
        };
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).unwrap_or_default()
    }

    pub fn save_atomic(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .with_context(|| format!("create state dir {}", parent.display()))?;

        let pid = std::process::id();
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("state.json");
        let tmp_path = parent.join(format!(".{file_name}.tmp.{pid}"));

        {
            let file = File::create(&tmp_path)
                .with_context(|| format!("create temp state {}", tmp_path.display()))?;
            let mut writer = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut writer, self)?;
            writer.flush()?;
        }

        fs::rename(&tmp_path, path)
            .with_context(|| format!("rename {} -> {}", tmp_path.display(), path.display()))?;
        Ok(())
    }

    pub fn frecency_score(&self, path: &str, now: u64) -> f64 {
        let Some(rec) = self.frecency.get(path) else {
            return 0.0;
        };
        let elapsed = now.saturating_sub(rec.last_accessed) as f64;
        rec.score * 0.5_f64.powf(elapsed / HALF_LIFE_SECS)
    }

    pub fn touch(&mut self, path: &str, now: u64) -> f64 {
        let current = self.frecency_score(path, now);
        let updated = current + 1.0;
        self.frecency.insert(
            path.to_string(),
            FrecencyRecord {
                score: updated,
                last_accessed: now,
            },
        );
        self.prune_if_needed(now);
        updated
    }

    pub fn is_pinned(&self, path: &str) -> bool {
        self.pinned.iter().any(|p| p == path)
    }

    pub fn pin(&mut self, path: &str) -> bool {
        if self.is_pinned(path) {
            return false;
        }
        self.pinned.push(path.to_string());
        true
    }

    pub fn unpin(&mut self, path: &str) -> bool {
        let before = self.pinned.len();
        self.pinned.retain(|p| p != path);
        self.pinned.len() != before
    }

    fn prune_if_needed(&mut self, now: u64) {
        if self.frecency.len() <= MAX_FRECENCY_RECORDS {
            return;
        }
        let mut scored: Vec<(String, f64)> = self
            .frecency
            .iter()
            .map(|(k, rec)| {
                let elapsed = now.saturating_sub(rec.last_accessed) as f64;
                let s = rec.score * 0.5_f64.powf(elapsed / HALF_LIFE_SECS);
                (k.clone(), s)
            })
            .filter(|(_, s)| *s >= 0.05)
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1));
        scored.truncate(MAX_FRECENCY_RECORDS);
        let keep: std::collections::HashSet<String> = scored.into_iter().map(|(k, _)| k).collect();
        self.frecency.retain(|k, _| keep.contains(k));
    }
}

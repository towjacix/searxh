use anyhow::{Context, Result, bail};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const MAGIC: &[u8; 4] = b"SRXH";
const FORMAT_VERSION: u16 = 1;
const REFRESH_COOLDOWN_SEC: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryKind {
    File = 0,
    Dir = 1,
    Symlink = 2,
}

impl EntryKind {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Dir,
            2 => Self::Symlink,
            _ => Self::File,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dir => "dir",
            Self::Symlink => "symlink",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub path: String,
    pub kind: EntryKind,
    pub size: u64,
    pub mtime: u64,
}

#[derive(Debug, Clone)]
pub struct IndexFile {
    pub built_at: u64,
    pub entries: Vec<IndexEntry>,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn is_stale(built_at: u64, ttl_sec: u64, now: u64) -> bool {
    if ttl_sec == 0 {
        return false;
    }
    now.saturating_sub(built_at) >= ttl_sec
}

pub fn write_index_atomic(path: &Path, built_at: u64, entries: &[IndexEntry]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create cache dir {}", parent.display()))?;

    let pid = std::process::id();
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("index.bin");
    let tmp_path = parent.join(format!(".{file_name}.tmp.{pid}"));

    {
        let file = File::create(&tmp_path)
            .with_context(|| format!("create temp index {}", tmp_path.display()))?;
        let mut w = BufWriter::with_capacity(64 * 1024, file);

        w.write_all(MAGIC)?;
        w.write_all(&FORMAT_VERSION.to_le_bytes())?;
        w.write_all(&built_at.to_le_bytes())?;
        let count = u32::try_from(entries.len()).unwrap_or(u32::MAX);
        w.write_all(&count.to_le_bytes())?;

        for entry in entries.iter().take(count as usize) {
            let bytes = entry.path.as_bytes();
            let path_len = u32::try_from(bytes.len()).context("path exceeds u32 length")?;
            w.write_all(&[entry.kind as u8])?;
            w.write_all(&entry.size.to_le_bytes())?;
            w.write_all(&entry.mtime.to_le_bytes())?;
            w.write_all(&path_len.to_le_bytes())?;
            w.write_all(bytes)?;
        }
        w.flush()?;
    }

    fs::rename(&tmp_path, path)
        .with_context(|| format!("rename {} -> {}", tmp_path.display(), path.display()))?;
    let lock_path = lock_path_for(path);
    let _ = fs::remove_file(lock_path);
    Ok(())
}

pub fn read_index(path: &Path) -> Result<IndexFile> {
    let file = File::open(path).with_context(|| format!("open index {}", path.display()))?;
    let mut r = BufReader::with_capacity(64 * 1024, file);

    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        bail!("invalid index magic");
    }

    let mut ver_buf = [0u8; 2];
    r.read_exact(&mut ver_buf)?;
    let version = u16::from_le_bytes(ver_buf);
    if version != FORMAT_VERSION {
        bail!("unsupported index version {version}");
    }

    let mut ts_buf = [0u8; 8];
    r.read_exact(&mut ts_buf)?;
    let built_at = u64::from_le_bytes(ts_buf);

    let mut cnt_buf = [0u8; 4];
    r.read_exact(&mut cnt_buf)?;
    let count = u32::from_le_bytes(cnt_buf) as usize;

    let mut entries = Vec::with_capacity(count.min(250_000));
    let mut header = [0u8; 21]; // 1 + 8 + 8 + 4
    let mut path_buf = Vec::with_capacity(256);

    for _ in 0..count {
        r.read_exact(&mut header)?;
        let kind = EntryKind::from_u8(header[0]);
        let size = u64::from_le_bytes(header[1..9].try_into()?);
        let mtime = u64::from_le_bytes(header[9..17].try_into()?);
        let path_len = u32::from_le_bytes(header[17..21].try_into()?) as usize;

        if path_len > 16 * 1024 {
            bail!("corrupt index entry path length {path_len}");
        }
        path_buf.resize(path_len, 0);
        r.read_exact(&mut path_buf)?;
        let path_str = String::from_utf8(path_buf.clone())?;

        entries.push(IndexEntry {
            path: path_str,
            kind,
            size,
            mtime,
        });
    }

    Ok(IndexFile { built_at, entries })
}

fn lock_path_for(cache_path: &Path) -> PathBuf {
    let mut os = cache_path.as_os_str().to_os_string();
    os.push(".lock");
    PathBuf::from(os)
}

pub fn spawn_background_refresh(config_path: &Path, cache_path: &Path, state_path: &Path) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let lock_path = lock_path_for(cache_path);
    if let Some(parent) = lock_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let now = now_secs();
    if let Ok(meta) = fs::metadata(&lock_path)
        && let Ok(mod_t) = meta.modified()
        && let Ok(age) = SystemTime::now().duration_since(mod_t)
        && age.as_secs() < REFRESH_COOLDOWN_SEC
    {
        return false;
    }

    if let Ok(mut f) = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&lock_path)
    {
        let _ = writeln!(f, "{now}");
    }

    let mut cmd = Command::new(exe);
    cmd.arg("--config")
        .arg(config_path)
        .arg("--cache")
        .arg(cache_path)
        .arg("--state")
        .arg(state_path)
        .arg("index")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    cmd.spawn().is_ok()
}

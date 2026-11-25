use anyhow::{Context, Result, bail};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const MAGIC: &[u8; 4] = b"SRXH";
pub const FORMAT_VERSION: u16 = 2;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexHeader {
    pub built_at: u64,
    pub generation: u64,
    pub config_fingerprint: u64,
    pub count: u32,
}

#[derive(Debug, Clone)]
pub struct IndexFile {
    pub built_at: u64,
    pub generation: u64,
    pub config_fingerprint: u64,
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

fn sidecar_lock_path(cache_path: &Path, suffix: &str) -> PathBuf {
    let mut os = cache_path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

fn open_lock_file(lock_path: &Path) -> Result<File> {
    if let Some(parent) = lock_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create lock dir {}", parent.display()))?;
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .with_context(|| format!("open lock file {}", lock_path.display()))
}

/// Exclusive advisory lock serializing all publications into `index.bin` and
/// ensuring generation numbers advance strictly monotonically.
pub struct IndexWriteLock {
    _file: File,
}

impl IndexWriteLock {
    pub fn acquire(cache_path: &Path) -> Result<Self> {
        let lock_path = sidecar_lock_path(cache_path, ".writer.lock");
        let file = open_lock_file(&lock_path)?;
        file.lock()
            .with_context(|| format!("acquire writer lock {}", lock_path.display()))?;
        Ok(Self { _file: file })
    }

    pub fn try_acquire(cache_path: &Path) -> Result<Option<Self>> {
        let lock_path = sidecar_lock_path(cache_path, ".writer.lock");
        let file = open_lock_file(&lock_path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(fs::TryLockError::WouldBlock) => Ok(None),
            Err(fs::TryLockError::Error(e)) => {
                Err(e).with_context(|| format!("try_lock writer lock {}", lock_path.display()))
            }
        }
    }
}

/// Exclusive advisory lock held for the lifetime of a `searxh watch` process so
/// duplicate watchers fail fast and background refresh skips redundant spawns.
pub struct WatcherLock {
    _file: File,
}

impl WatcherLock {
    pub fn try_acquire(cache_path: &Path) -> Result<Option<Self>> {
        let lock_path = sidecar_lock_path(cache_path, ".watch.lock");
        let file = open_lock_file(&lock_path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(fs::TryLockError::WouldBlock) => Ok(None),
            Err(fs::TryLockError::Error(e)) => {
                Err(e).with_context(|| format!("try_lock watcher lock {}", lock_path.display()))
            }
        }
    }
}

pub fn is_watcher_active(cache_path: &Path) -> bool {
    let lock_path = sidecar_lock_path(cache_path, ".watch.lock");
    if !lock_path.exists() {
        return false;
    }
    let Ok(file) = File::open(&lock_path) else {
        return false;
    };
    matches!(file.try_lock(), Err(fs::TryLockError::WouldBlock))
}

fn read_header_from_reader<R: Read>(r: &mut R) -> Result<IndexHeader> {
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

    let mut u64_buf = [0u8; 8];
    r.read_exact(&mut u64_buf)?;
    let built_at = u64::from_le_bytes(u64_buf);

    r.read_exact(&mut u64_buf)?;
    let generation = u64::from_le_bytes(u64_buf);

    r.read_exact(&mut u64_buf)?;
    let config_fingerprint = u64::from_le_bytes(u64_buf);

    let mut cnt_buf = [0u8; 4];
    r.read_exact(&mut cnt_buf)?;
    let count = u32::from_le_bytes(cnt_buf);

    Ok(IndexHeader {
        built_at,
        generation,
        config_fingerprint,
        count,
    })
}

pub fn read_index_header(path: &Path) -> Result<IndexHeader> {
    let file = File::open(path).with_context(|| format!("open index {}", path.display()))?;
    let mut r = BufReader::with_capacity(64, file);
    read_header_from_reader(&mut r)
}

/// Publish a complete snapshot under the exclusive writer lock, advancing the
/// persisted generation monotonically.
pub fn publish_index(
    path: &Path,
    built_at: u64,
    config_fingerprint: u64,
    entries: &[IndexEntry],
) -> Result<u64> {
    let _guard = IndexWriteLock::acquire(path)?;
    publish_index_locked(path, built_at, config_fingerprint, entries)
}

pub fn publish_index_locked(
    path: &Path,
    built_at: u64,
    config_fingerprint: u64,
    entries: &[IndexEntry],
) -> Result<u64> {
    let prev_gen = read_index_header(path).map(|h| h.generation).unwrap_or(0);
    let generation = prev_gen.saturating_add(1);

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
        w.write_all(&generation.to_le_bytes())?;
        w.write_all(&config_fingerprint.to_le_bytes())?;
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
    let cooldown_path = refresh_cooldown_path(path);
    let _ = fs::remove_file(cooldown_path);
    Ok(generation)
}

pub fn write_index_atomic(path: &Path, built_at: u64, entries: &[IndexEntry]) -> Result<()> {
    publish_index(path, built_at, 0, entries)?;
    Ok(())
}

pub fn read_index(path: &Path) -> Result<IndexFile> {
    let file = File::open(path).with_context(|| format!("open index {}", path.display()))?;
    let mut r = BufReader::with_capacity(64 * 1024, file);

    let header = read_header_from_reader(&mut r)?;
    let count = header.count as usize;

    let mut entries = Vec::with_capacity(count.min(250_000));
    let mut rec_hdr = [0u8; 21]; // 1 + 8 + 8 + 4
    let mut path_buf = Vec::with_capacity(256);

    for _ in 0..count {
        r.read_exact(&mut rec_hdr)?;
        let kind = EntryKind::from_u8(rec_hdr[0]);
        let size = u64::from_le_bytes(rec_hdr[1..9].try_into()?);
        let mtime = u64::from_le_bytes(rec_hdr[9..17].try_into()?);
        let path_len = u32::from_le_bytes(rec_hdr[17..21].try_into()?) as usize;

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

    Ok(IndexFile {
        built_at: header.built_at,
        generation: header.generation,
        config_fingerprint: header.config_fingerprint,
        entries,
    })
}

fn refresh_cooldown_path(cache_path: &Path) -> PathBuf {
    sidecar_lock_path(cache_path, ".refresh")
}

pub fn spawn_background_refresh(config_path: &Path, cache_path: &Path, state_path: &Path) -> bool {
    if is_watcher_active(cache_path) {
        return false;
    }
    if matches!(IndexWriteLock::try_acquire(cache_path), Ok(None)) {
        return false;
    }
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let cooldown_path = refresh_cooldown_path(cache_path);
    if let Some(parent) = cooldown_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let now = now_secs();
    if let Ok(meta) = fs::metadata(&cooldown_path)
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
        .open(&cooldown_path)
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

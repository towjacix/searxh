use anyhow::{Context, Result, bail};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const MAGIC: &[u8; 4] = b"SRXH";
pub const FORMAT_VERSION: u16 = 3;
const HEADER_LEN: usize = 42;
const ENTRY_STRIDE: usize = 28;
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

#[derive(Debug, Clone, Copy)]
pub struct BorrowedEntry<'a> {
    pub path: &'a str,
    pub basename: &'a str,
    pub kind: EntryKind,
    pub size: u64,
    pub mtime: u64,
}

impl<'a> BorrowedEntry<'a> {
    pub fn to_owned_entry(self) -> IndexEntry {
        IndexEntry {
            path: self.path.to_owned(),
            kind: self.kind,
            size: self.size,
            mtime: self.mtime,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RawEntryMeta {
    path_offset: u32,
    path_len: u32,
    basename_offset: u16,
    kind: EntryKind,
    size: u64,
    mtime: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexHeader {
    pub built_at: u64,
    pub generation: u64,
    pub config_fingerprint: u64,
    pub count: u32,
    pub string_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct IndexFile {
    pub built_at: u64,
    pub generation: u64,
    pub config_fingerprint: u64,
    pub entries: Vec<IndexEntry>,
}

/// Zero-allocation borrowed view backed by a single contiguous file buffer +
/// fixed-stride entry table (`FORMAT_VERSION = 3`).
pub struct IndexSnapshot {
    pub built_at: u64,
    pub generation: u64,
    pub config_fingerprint: u64,
    buf: Vec<u8>,
    str_start: usize,
    str_len: usize,
    metas: Vec<RawEntryMeta>,
}

impl IndexSnapshot {
    pub fn open(path: &Path) -> Result<Self> {
        let buf = fs::read(path).with_context(|| format!("read index {}", path.display()))?;
        Self::from_bytes(buf)
    }

    pub fn from_bytes(buf: Vec<u8>) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            bail!("truncated index header");
        }
        let mut hdr_slice = &buf[..HEADER_LEN];
        let header = read_header_from_reader(&mut hdr_slice)?;
        let count = header.count as usize;
        let table_bytes = count
            .checked_mul(ENTRY_STRIDE)
            .context("entry table overflow")?;
        let str_start = HEADER_LEN
            .checked_add(table_bytes)
            .context("string table start overflow")?;
        let str_len = usize::try_from(header.string_bytes).context("string table size overflow")?;
        let expected_end = str_start
            .checked_add(str_len)
            .context("index total length overflow")?;
        if buf.len() < expected_end {
            bail!("truncated index body");
        }

        // Validate the entire string arena once with SIMD UTF-8 validation.
        let arena = &buf[str_start..str_start + str_len];
        std::str::from_utf8(arena).context("corrupt UTF-8 string arena in index")?;

        #[inline]
        fn is_utf8_boundary(bytes: &[u8], idx: usize) -> bool {
            idx == bytes.len() || (bytes.get(idx).is_some_and(|&b| (b as i8) >= -0x40))
        }

        let mut metas = Vec::with_capacity(count);
        for i in 0..count {
            let off = HEADER_LEN + i * ENTRY_STRIDE;
            let rec = &buf[off..off + ENTRY_STRIDE];
            let path_offset = u32::from_le_bytes(rec[0..4].try_into()?);
            let path_len = u32::from_le_bytes(rec[4..8].try_into()?);
            let basename_offset = u16::from_le_bytes(rec[8..10].try_into()?);
            let kind = EntryKind::from_u8(rec[10]);
            let size = u64::from_le_bytes(rec[12..20].try_into()?);
            let mtime = u64::from_le_bytes(rec[20..28].try_into()?);

            let start = path_offset as usize;
            let len = path_len as usize;
            let end = start
                .checked_add(len)
                .context("corrupt path range in index")?;
            if end > str_len {
                bail!("index entry path range out of bounds");
            }
            // Since `arena` is already valid UTF-8, checking start/end codepoint boundaries
            // guarantees `&arena[start..end]` and its basename slice are valid UTF-8 in O(1).
            if !is_utf8_boundary(arena, start) || !is_utf8_boundary(arena, end) {
                bail!("index entry does not sit on UTF-8 char boundaries");
            }
            if basename_offset != u16::MAX {
                let boff = basename_offset as usize;
                if boff > len || !is_utf8_boundary(arena, start + boff) {
                    bail!("corrupt basename char boundary in index");
                }
            }

            metas.push(RawEntryMeta {
                path_offset,
                path_len,
                basename_offset,
                kind,
                size,
                mtime,
            });
        }

        Ok(Self {
            built_at: header.built_at,
            generation: header.generation,
            config_fingerprint: header.config_fingerprint,
            buf,
            str_start,
            str_len,
            metas,
        })
    }

    pub fn len(&self) -> usize {
        self.metas.len()
    }

    pub fn is_empty(&self) -> bool {
        self.metas.is_empty()
    }

    #[inline]
    pub fn get(&self, idx: usize) -> BorrowedEntry<'_> {
        let meta = &self.metas[idx];
        let start = self.str_start + meta.path_offset as usize;
        let len = meta.path_len as usize;
        debug_assert!(start + len <= self.str_start + self.str_len);
        // Validated upfront in `from_bytes`.
        let path = unsafe { std::str::from_utf8_unchecked(&self.buf[start..start + len]) };
        let basename = if meta.basename_offset == u16::MAX {
            compute_basename(path)
        } else {
            let clean = path.strip_suffix('/').unwrap_or(path);
            let boff = meta.basename_offset as usize;
            if boff <= clean.len() {
                &clean[boff..]
            } else {
                compute_basename(path)
            }
        };
        BorrowedEntry {
            path,
            basename,
            kind: meta.kind,
            size: meta.size,
            mtime: meta.mtime,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = BorrowedEntry<'_>> {
        (0..self.metas.len()).map(move |i| self.get(i))
    }

    pub fn to_owned_file(&self) -> IndexFile {
        IndexFile {
            built_at: self.built_at,
            generation: self.generation,
            config_fingerprint: self.config_fingerprint,
            entries: self.iter().map(BorrowedEntry::to_owned_entry).collect(),
        }
    }
}

#[inline]
fn compute_basename(path: &str) -> &str {
    if path == "/" {
        return "/";
    }
    let clean = path.strip_suffix('/').unwrap_or(path);
    match clean.rfind('/') {
        Some(idx) => &clean[idx + 1..],
        None => clean,
    }
}

#[inline]
fn compute_basename_offset(path: &str) -> u16 {
    if path == "/" {
        return 0;
    }
    let clean = path.strip_suffix('/').unwrap_or(path);
    let off = match clean.rfind('/') {
        Some(idx) => idx + 1,
        None => 0,
    };
    u16::try_from(off).unwrap_or(u16::MAX)
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

    r.read_exact(&mut u64_buf)?;
    let string_bytes = u64::from_le_bytes(u64_buf);

    Ok(IndexHeader {
        built_at,
        generation,
        config_fingerprint,
        count,
        string_bytes,
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

    let count = u32::try_from(entries.len()).unwrap_or(u32::MAX);
    let slice = &entries[..count as usize];

    let mut string_bytes = 0u64;
    for e in slice {
        string_bytes = string_bytes
            .checked_add(e.path.len() as u64)
            .context("string table byte size overflow")?;
    }
    if string_bytes > u32::MAX as u64 {
        bail!("string table exceeds 4 GiB offset limit");
    }

    {
        let file = File::create(&tmp_path)
            .with_context(|| format!("create temp index {}", tmp_path.display()))?;
        let mut w = BufWriter::with_capacity(64 * 1024, file);

        // 42-byte fixed header
        w.write_all(MAGIC)?;
        w.write_all(&FORMAT_VERSION.to_le_bytes())?;
        w.write_all(&built_at.to_le_bytes())?;
        w.write_all(&generation.to_le_bytes())?;
        w.write_all(&config_fingerprint.to_le_bytes())?;
        w.write_all(&count.to_le_bytes())?;
        w.write_all(&string_bytes.to_le_bytes())?;

        // 28-byte fixed entry records
        let mut cursor = 0u32;
        for entry in slice {
            let bytes = entry.path.as_bytes();
            let path_len = u32::try_from(bytes.len()).context("path exceeds u32 length")?;
            let boff = compute_basename_offset(&entry.path);
            w.write_all(&cursor.to_le_bytes())?;
            w.write_all(&path_len.to_le_bytes())?;
            w.write_all(&boff.to_le_bytes())?;
            w.write_all(&[entry.kind as u8, 0u8])?;
            w.write_all(&entry.size.to_le_bytes())?;
            w.write_all(&entry.mtime.to_le_bytes())?;
            cursor = cursor
                .checked_add(path_len)
                .context("string offset overflow")?;
        }

        // Contiguous UTF-8 path string arena
        for entry in slice {
            w.write_all(entry.path.as_bytes())?;
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
    let snap = IndexSnapshot::open(path)?;
    Ok(snap.to_owned_file())
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

use crate::config::file_category;
use crate::index::EntryKind;
use crate::scanner::mtime_secs;
use crate::search::{basename, format_unix_mode};
use anyhow::{Context, Result};
use exif::{In, Reader as ExifReader, Tag, Value as ExifValue};
use serde::Serialize;
use std::fs::{self, File, FileType};
use std::io::{BufReader, Read};
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct InspectOptions {
    pub max_bytes: usize,
    pub max_lines: usize,
    pub max_entries: usize,
    pub include_gps: bool,
}

impl Default for InspectOptions {
    fn default() -> Self {
        Self {
            max_bytes: 262_144,
            max_lines: 2000,
            max_entries: 40,
            include_gps: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DirEntryPreview {
    pub name: String,
    pub path: String,
    pub kind: &'static str,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DirSummary {
    pub total_entries: usize,
    pub files: usize,
    pub dirs: usize,
    pub symlinks: usize,
    pub direct_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GpsCoords {
    pub lat: f64,
    pub lon: f64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ExifMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub camera: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taken_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposure: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aperture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iso: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focal_length: Option<String>,
    pub has_gps: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gps: Option<GpsCoords>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImageMetadata {
    pub width: usize,
    pub height: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exif: Option<ExifMetadata>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectResult {
    pub path: String,
    pub name: String,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_broken: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_path: Option<String>,
    pub category: &'static str,
    pub size: u64,
    pub mtime: u64,
    pub mode: String,
    pub preview_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_entries: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir_summary: Option<DirSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<DirEntryPreview>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageMetadata>,
}

pub fn inspect_path(path: &Path, opts: &InspectOptions) -> Result<InspectResult> {
    let lmeta = fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let lft = lmeta.file_type();
    let is_symlink = lft.is_symlink();
    let symlink_target = if is_symlink {
        fs::read_link(path)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    } else {
        None
    };

    let target_meta = if is_symlink {
        fs::metadata(path).ok()
    } else {
        None
    };
    let symlink_broken = if is_symlink {
        Some(target_meta.is_none())
    } else {
        None
    };
    let resolved_path = if is_symlink && target_meta.is_some() {
        fs::canonicalize(path)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    } else {
        None
    };

    let effective_meta = target_meta.as_ref().unwrap_or(&lmeta);
    let is_dir = effective_meta.is_dir();

    let kind = if is_dir {
        EntryKind::Dir
    } else if is_symlink {
        EntryKind::Symlink
    } else {
        EntryKind::File
    };

    let path_str = path.to_string_lossy().into_owned();
    let name = basename(&path_str).to_string();
    let category = file_category(&path_str, is_dir);
    let size = effective_meta.len();
    let mtime = mtime_secs(effective_meta);
    let mode = format_unix_mode(lmeta.permissions().mode(), kind);

    if is_dir {
        let (entries, summary) = read_dir_preview(path, opts.max_entries)?;
        return Ok(InspectResult {
            path: path_str,
            name,
            kind: kind.as_str(),
            mime: Some("inode/directory".to_string()),
            symlink_target,
            symlink_broken,
            resolved_path,
            category,
            size,
            mtime,
            mode,
            preview_kind: "dir",
            text: None,
            encoding: None,
            truncated: None,
            lines: None,
            total_entries: Some(summary.total_entries),
            dir_summary: Some(summary),
            entries: Some(entries),
            image: None,
        });
    }

    if is_symlink && target_meta.is_none() {
        // Broken symlink
        return Ok(InspectResult {
            path: path_str,
            name,
            kind: kind.as_str(),
            mime: Some("inode/symlink".to_string()),
            symlink_target,
            symlink_broken,
            resolved_path,
            category,
            size,
            mtime,
            mode,
            preview_kind: "none",
            text: None,
            encoding: None,
            truncated: None,
            lines: None,
            total_entries: None,
            dir_summary: None,
            entries: None,
            image: None,
        });
    }

    let effective_ft = effective_meta.file_type();
    if !effective_ft.is_file() {
        // Never open FIFOs, sockets, or device nodes — reading them can block indefinitely.
        return Ok(InspectResult {
            path: path_str,
            name,
            kind: kind.as_str(),
            mime: Some(special_file_mime(effective_ft).to_string()),
            symlink_target,
            symlink_broken,
            resolved_path,
            category,
            size,
            mtime,
            mode,
            preview_kind: "none",
            text: None,
            encoding: None,
            truncated: None,
            lines: None,
            total_entries: None,
            dir_summary: None,
            entries: None,
            image: None,
        });
    }

    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut raw = Vec::new();
    let read_cap = opts.max_bytes.saturating_add(1);
    file.take(read_cap as u64).read_to_end(&mut raw)?;

    let sniff_len = raw.len().min(8192);
    let sniff_slice = &raw[..sniff_len];
    let detected_mime = sniff_mime(&path_str, sniff_slice);
    let is_image_magic = detected_mime
        .as_deref()
        .is_some_and(|m| m.starts_with("image/"));

    if category == "image" || is_image_magic {
        let image = inspect_image(path, opts.include_gps);
        if image.is_some() || category == "image" {
            return Ok(InspectResult {
                path: path_str,
                name,
                kind: kind.as_str(),
                mime: detected_mime.or_else(|| Some("image/unknown".to_string())),
                symlink_target,
                symlink_broken,
                resolved_path,
                category: if is_image_magic { "image" } else { category },
                size,
                mtime,
                mode,
                preview_kind: "image",
                text: None,
                encoding: None,
                truncated: None,
                lines: None,
                total_entries: None,
                dir_summary: None,
                entries: None,
                image,
            });
        }
    }

    if is_likely_binary(sniff_slice) {
        return Ok(InspectResult {
            path: path_str,
            name,
            kind: kind.as_str(),
            mime: detected_mime.or_else(|| Some("application/octet-stream".to_string())),
            symlink_target,
            symlink_broken,
            resolved_path,
            category,
            size,
            mtime,
            mode,
            preview_kind: "binary",
            text: None,
            encoding: None,
            truncated: None,
            lines: None,
            total_entries: None,
            dir_summary: None,
            entries: None,
            image: None,
        });
    }

    let hit_byte_cap = raw.len() > opts.max_bytes;
    let slice = if hit_byte_cap {
        &raw[..opts.max_bytes]
    } else {
        &raw[..]
    };

    let (safe_str, encoding) = decode_utf8_prefix_safe(slice);
    let (text, line_count, hit_line_cap) = truncate_lines(&safe_str, opts.max_lines);
    let text_mime = detected_mime.unwrap_or_else(|| text_mime_for_path(&path_str, sniff_slice));

    Ok(InspectResult {
        path: path_str,
        name,
        kind: kind.as_str(),
        mime: Some(text_mime),
        symlink_target,
        symlink_broken,
        resolved_path,
        category,
        size,
        mtime,
        mode,
        preview_kind: "text",
        text: Some(text),
        encoding: Some(encoding),
        truncated: Some(hit_byte_cap || hit_line_cap),
        lines: Some(line_count),
        total_entries: None,
        dir_summary: None,
        entries: None,
        image: None,
    })
}

fn sniff_mime(path: &str, head: &[u8]) -> Option<String> {
    if head.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("image/png".to_string());
    }
    if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg".to_string());
    }
    if head.starts_with(b"GIF87a") || head.starts_with(b"GIF89a") {
        return Some("image/gif".to_string());
    }
    if head.len() >= 12 && &head[0..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        return Some("image/webp".to_string());
    }
    if head.starts_with(b"BM") && head.len() >= 14 {
        return Some("image/bmp".to_string());
    }
    if (head.starts_with(b"II*\0") || head.starts_with(b"MM\0*")) && head.len() >= 8 {
        return Some("image/tiff".to_string());
    }
    if head.len() >= 12 && &head[4..8] == b"ftyp" {
        let brand = &head[8..12];
        if brand == b"avif" || brand == b"avis" {
            return Some("image/avif".to_string());
        }
        if matches!(brand, b"heic" | b"heix" | b"mif1" | b"msf1") {
            return Some("image/heic".to_string());
        }
        return Some("video/mp4".to_string());
    }
    if head.starts_with(&[0xFF, 0x0A]) || head.starts_with(b"\x00\x00\x00\x0CJXL ") {
        return Some("image/jxl".to_string());
    }
    if head.starts_with(b"%PDF-") {
        return Some("application/pdf".to_string());
    }
    if head.starts_with(b"\x7FELF") {
        return Some("application/x-elf".to_string());
    }
    if head.starts_with(b"SQLite format 3\0") {
        return Some("application/vnd.sqlite3".to_string());
    }
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        let ext = Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase());
        return Some(match ext.as_deref() {
            Some("docx") => {
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    .to_string()
            }
            Some("xlsx") => {
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".to_string()
            }
            Some("pptx") => {
                "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                    .to_string()
            }
            _ => "application/zip".to_string(),
        });
    }
    if head.starts_with(&[0x1F, 0x8B]) {
        return Some("application/gzip".to_string());
    }
    if head.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Some("application/zstd".to_string());
    }
    if head.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        return Some("application/x-xz".to_string());
    }
    if head.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Some("application/x-7z-compressed".to_string());
    }
    if head.starts_with(b"Rar!") {
        return Some("application/vnd.rar".to_string());
    }
    if head.starts_with(b"fLaC") {
        return Some("audio/flac".to_string());
    }
    if head.starts_with(b"OggS") {
        return Some("audio/ogg".to_string());
    }
    if head.starts_with(b"ID3") || (head.len() >= 2 && head[0] == 0xFF && (head[1] & 0xE0) == 0xE0)
    {
        return Some("audio/mpeg".to_string());
    }
    if head.len() >= 12 && &head[0..4] == b"RIFF" && &head[8..12] == b"WAVE" {
        return Some("audio/wav".to_string());
    }
    if head.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return Some("video/x-matroska".to_string());
    }
    // Check SVG XML text
    if let Ok(s) = std::str::from_utf8(head) {
        let trimmed = s.trim_start();
        if trimmed.starts_with("<svg") || (trimmed.starts_with("<?xml") && trimmed.contains("<svg"))
        {
            return Some("image/svg+xml".to_string());
        }
    }
    None
}

fn text_mime_for_path(path: &str, head: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(head)
        && let Some(first_line) = s.lines().next()
        && let Some(shebang) = first_line.strip_prefix("#!")
    {
        if shebang.contains("python") {
            return "text/x-python".to_string();
        }
        if shebang.contains("sh") || shebang.contains("zsh") {
            return "text/x-shellscript".to_string();
        }
    }
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("rs") => "text/x-rust".to_string(),
        Some("qml") => "text/x-qml".to_string(),
        Some("js" | "mjs" | "cjs") => "text/javascript".to_string(),
        Some("ts") => "text/typescript".to_string(),
        Some("py") => "text/x-python".to_string(),
        Some("sh" | "bash" | "zsh") => "text/x-shellscript".to_string(),
        Some("go") => "text/x-go".to_string(),
        Some("json") => "application/json".to_string(),
        Some("toml") => "application/toml".to_string(),
        Some("yaml" | "yml") => "application/yaml".to_string(),
        Some("md") => "text/markdown".to_string(),
        Some("html" | "htm") => "text/html".to_string(),
        Some("css") => "text/css".to_string(),
        Some("csv") => "text/csv".to_string(),
        _ => "text/plain".to_string(),
    }
}

fn read_dir_preview(path: &Path, max_entries: usize) -> Result<(Vec<DirEntryPreview>, DirSummary)> {
    let mut all = Vec::new();
    let mut files = 0usize;
    let mut dirs = 0usize;
    let mut symlinks = 0usize;
    let mut direct_bytes = 0u64;

    let rd = fs::read_dir(path).with_context(|| format!("read_dir {}", path.display()))?;
    for entry_res in rd {
        let Ok(entry) = entry_res else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        let p = entry.path();
        let meta = entry.metadata().ok();
        let ft = entry.file_type().ok();
        let is_dir = ft.is_some_and(|t| t.is_dir());
        let is_sym = ft.is_some_and(|t| t.is_symlink());
        let kind = if is_dir {
            dirs += 1;
            "dir"
        } else if is_sym {
            symlinks += 1;
            "symlink"
        } else {
            files += 1;
            "file"
        };
        let size = meta.map(|m| m.len()).unwrap_or(0);
        if !is_dir {
            direct_bytes = direct_bytes.saturating_add(size);
        }
        all.push((
            !is_dir,
            name.to_ascii_lowercase(),
            DirEntryPreview {
                name,
                path: p.to_string_lossy().into_owned(),
                kind,
                size,
            },
        ));
    }
    let total_entries = all.len();
    all.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let preview = all
        .into_iter()
        .take(max_entries)
        .map(|(_, _, item)| item)
        .collect();
    Ok((
        preview,
        DirSummary {
            total_entries,
            files,
            dirs,
            symlinks,
            direct_bytes,
        },
    ))
}

fn is_likely_binary(sample: &[u8]) -> bool {
    if sample.is_empty() {
        return false;
    }
    if sample.contains(&0) {
        return true;
    }
    let ctrl_count = sample
        .iter()
        .filter(|&&b| b < 0x20 && !matches!(b, b'\n' | b'\r' | b'\t' | 0x0C | 0x1B))
        .count();
    ctrl_count * 10 > sample.len()
}

fn decode_utf8_prefix_safe(slice: &[u8]) -> (String, &'static str) {
    match std::str::from_utf8(slice) {
        Ok(s) => (s.to_string(), "utf-8"),
        Err(e) if e.error_len().is_none() => {
            // Cut neatly before incomplete trailing multi-byte char
            (
                String::from_utf8_lossy(&slice[..e.valid_up_to()]).into_owned(),
                "utf-8",
            )
        }
        Err(_) => (String::from_utf8_lossy(slice).into_owned(), "utf-8-lossy"),
    }
}

fn truncate_lines(input: &str, max_lines: usize) -> (String, usize, bool) {
    if max_lines == 0 {
        return (String::new(), 0, !input.is_empty());
    }
    let mut out = String::new();
    let mut lines_taken = 0usize;
    let mut truncated = false;
    for (idx, line) in input.split('\n').enumerate() {
        if idx >= max_lines {
            truncated = true;
            break;
        }
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(line);
        lines_taken += 1;
    }
    (out, lines_taken, truncated)
}

fn inspect_image(path: &Path, include_gps: bool) -> Option<ImageMetadata> {
    let dims = imagesize::size(path).ok();
    let fmt = File::open(path)
        .ok()
        .and_then(|mut f| {
            let mut hdr = [0u8; 32];
            let n = f.read(&mut hdr).ok()?;
            imagesize::image_type(&hdr[..n]).ok()
        })
        .map(image_type_label);

    let exif = read_exif(path, include_gps);
    match (dims, exif) {
        (Some(d), ex) => Some(ImageMetadata {
            width: d.width,
            height: d.height,
            format: fmt,
            exif: ex,
        }),
        (None, Some(ex)) => Some(ImageMetadata {
            width: 0,
            height: 0,
            format: fmt,
            exif: Some(ex),
        }),
        (None, None) => None,
    }
}

fn image_type_label(t: imagesize::ImageType) -> String {
    format!("{t:?}").to_ascii_lowercase()
}

fn read_exif(path: &Path, include_gps: bool) -> Option<ExifMetadata> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    let exif = ExifReader::new().read_from_container(&mut reader).ok()?;

    let field_str = |tag: Tag| -> Option<String> {
        exif.get_field(tag, In::PRIMARY)
            .map(|f| {
                f.display_value()
                    .to_string()
                    .trim_matches('"')
                    .trim()
                    .to_string()
            })
            .filter(|s| !s.is_empty())
    };

    let make = field_str(Tag::Make);
    let model = field_str(Tag::Model);
    let camera = match (make, model) {
        (Some(mk), Some(md)) => {
            if md
                .to_ascii_lowercase()
                .starts_with(&mk.to_ascii_lowercase())
            {
                Some(md)
            } else {
                Some(format!("{mk} {md}"))
            }
        }
        (None, Some(md)) => Some(md),
        (Some(mk), None) => Some(mk),
        (None, None) => None,
    };

    let lens = field_str(Tag::LensModel);
    let taken_at = field_str(Tag::DateTimeOriginal).or_else(|| field_str(Tag::DateTime));

    let exposure = exif.get_field(Tag::ExposureTime, In::PRIMARY).map(|f| {
        if let ExifValue::Rational(ref v) = f.value
            && let Some(r) = v.first()
            && r.denom != 0
        {
            if r.num < r.denom && r.num > 0 {
                let denom = (r.denom as f64 / r.num as f64).round() as u32;
                return format!("1/{denom}s");
            }
            return format!("{:.2}s", r.to_f64());
        }
        f.display_value().with_unit(&exif).to_string()
    });

    let aperture = exif.get_field(Tag::FNumber, In::PRIMARY).and_then(|f| {
        if let ExifValue::Rational(ref v) = f.value
            && let Some(r) = v.first()
            && r.denom != 0
        {
            return Some(format!("f/{:.1}", r.to_f64()));
        }
        None
    });

    let iso = exif
        .get_field(Tag::PhotographicSensitivity, In::PRIMARY)
        .and_then(|f| f.value.get_uint(0));

    let focal_length = exif.get_field(Tag::FocalLength, In::PRIMARY).and_then(|f| {
        if let ExifValue::Rational(ref v) = f.value
            && let Some(r) = v.first()
            && r.denom != 0
        {
            let mm = r.to_f64();
            if (mm - mm.round()).abs() < 0.05 {
                return Some(format!("{}mm", mm.round() as u32));
            }
            return Some(format!("{mm:.1}mm"));
        }
        None
    });

    let lat = parse_gps_coord(&exif, Tag::GPSLatitude, Tag::GPSLatitudeRef, 'S');
    let lon = parse_gps_coord(&exif, Tag::GPSLongitude, Tag::GPSLongitudeRef, 'W');
    let has_gps = lat.is_some() && lon.is_some();
    let gps = if include_gps {
        lat.zip(lon).map(|(lat, lon)| GpsCoords { lat, lon })
    } else {
        None
    };

    if camera.is_none()
        && lens.is_none()
        && taken_at.is_none()
        && exposure.is_none()
        && aperture.is_none()
        && iso.is_none()
        && focal_length.is_none()
        && !has_gps
    {
        return None;
    }

    Some(ExifMetadata {
        camera,
        lens,
        taken_at,
        exposure,
        aperture,
        iso,
        focal_length,
        has_gps,
        gps,
    })
}

fn parse_gps_coord(exif: &exif::Exif, coord_tag: Tag, ref_tag: Tag, neg_ref: char) -> Option<f64> {
    let field = exif.get_field(coord_tag, In::PRIMARY)?;
    let ExifValue::Rational(ref parts) = field.value else {
        return None;
    };
    if parts.len() < 3 || parts[0].denom == 0 || parts[1].denom == 0 || parts[2].denom == 0 {
        return None;
    }
    let deg = parts[0].to_f64();
    let min = parts[1].to_f64();
    let sec = parts[2].to_f64();
    let mut val = deg + min / 60.0 + sec / 3600.0;
    if let Some(ref_f) = exif.get_field(ref_tag, In::PRIMARY) {
        let s = ref_f.display_value().to_string();
        if s.trim().starts_with(neg_ref) {
            val = -val;
        }
    }
    Some(val)
}

fn special_file_mime(ft: FileType) -> &'static str {
    #[cfg(unix)]
    {
        if ft.is_fifo() {
            return "inode/fifo";
        }
        if ft.is_char_device() {
            return "inode/chardevice";
        }
        if ft.is_block_device() {
            return "inode/blockdevice";
        }
        if ft.is_socket() {
            return "inode/socket";
        }
    }
    let _ = ft;
    "inode/special"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn inspect_skips_fifo_and_symlink_to_fifo_without_blocking() {
        let tmp = TempDir::new().unwrap();
        let fifo = tmp.path().join("live_pipe");
        let status = Command::new("mkfifo").arg(&fifo).status().unwrap();
        assert!(status.success(), "mkfifo failed");

        let fifo_res = inspect_path(&fifo, &InspectOptions::default()).unwrap();
        assert_eq!(fifo_res.preview_kind, "none");
        assert_eq!(fifo_res.mime.as_deref(), Some("inode/fifo"));

        let link = tmp.path().join("pipe_link");
        std::os::unix::fs::symlink(&fifo, &link).unwrap();
        let link_res = inspect_path(&link, &InspectOptions::default()).unwrap();
        assert_eq!(link_res.kind, "symlink");
        assert_eq!(link_res.symlink_broken, Some(false));
        assert_eq!(link_res.preview_kind, "none");
        assert_eq!(link_res.mime.as_deref(), Some("inode/fifo"));
    }
}

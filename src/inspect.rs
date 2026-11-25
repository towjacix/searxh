use crate::config::file_category;
use crate::index::EntryKind;
use crate::scanner::mtime_secs;
use crate::search::{basename, format_unix_mode};
use anyhow::{Context, Result};
use exif::{In, Reader as ExifReader, Tag, Value as ExifValue};
use serde::Serialize;
use std::fs::{self, File};
use std::io::{BufReader, Read};
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
    pub symlink_target: Option<String>,
    pub category: &'static str,
    pub size: u64,
    pub mtime: u64,
    pub mode: String,
    pub preview_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_entries: Option<usize>,
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
        let (entries, total_entries) = read_dir_preview(path, opts.max_entries)?;
        return Ok(InspectResult {
            path: path_str,
            name,
            kind: kind.as_str(),
            symlink_target,
            category,
            size,
            mtime,
            mode,
            preview_kind: "dir",
            text: None,
            truncated: None,
            lines: None,
            total_entries: Some(total_entries),
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
            symlink_target,
            category,
            size,
            mtime,
            mode,
            preview_kind: "none",
            text: None,
            truncated: None,
            lines: None,
            total_entries: None,
            entries: None,
            image: None,
        });
    }

    if category == "image" {
        let image = inspect_image(path, opts.include_gps);
        return Ok(InspectResult {
            path: path_str,
            name,
            kind: kind.as_str(),
            symlink_target,
            category,
            size,
            mtime,
            mode,
            preview_kind: "image",
            text: None,
            truncated: None,
            lines: None,
            total_entries: None,
            entries: None,
            image,
        });
    }

    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut raw = Vec::new();
    let read_cap = opts.max_bytes.saturating_add(1);
    file.take(read_cap as u64).read_to_end(&mut raw)?;

    let sniff_len = raw.len().min(8192);
    if is_likely_binary(&raw[..sniff_len]) {
        return Ok(InspectResult {
            path: path_str,
            name,
            kind: kind.as_str(),
            symlink_target,
            category,
            size,
            mtime,
            mode,
            preview_kind: "binary",
            text: None,
            truncated: None,
            lines: None,
            total_entries: None,
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

    let safe_str = decode_utf8_prefix_safe(slice);
    let (text, line_count, hit_line_cap) = truncate_lines(&safe_str, opts.max_lines);

    Ok(InspectResult {
        path: path_str,
        name,
        kind: kind.as_str(),
        symlink_target,
        category,
        size,
        mtime,
        mode,
        preview_kind: "text",
        text: Some(text),
        truncated: Some(hit_byte_cap || hit_line_cap),
        lines: Some(line_count),
        total_entries: None,
        entries: None,
        image: None,
    })
}

fn read_dir_preview(path: &Path, max_entries: usize) -> Result<(Vec<DirEntryPreview>, usize)> {
    let mut all = Vec::new();
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
            "dir"
        } else if is_sym {
            "symlink"
        } else {
            "file"
        };
        let size = meta.map(|m| m.len()).unwrap_or(0);
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
    let total = all.len();
    all.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let preview = all
        .into_iter()
        .take(max_entries)
        .map(|(_, _, item)| item)
        .collect();
    Ok((preview, total))
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

fn decode_utf8_prefix_safe(slice: &[u8]) -> String {
    match std::str::from_utf8(slice) {
        Ok(s) => s.to_string(),
        Err(e) if e.error_len().is_none() => {
            // Cut neatly before incomplete trailing multi-byte char
            String::from_utf8_lossy(&slice[..e.valid_up_to()]).into_owned()
        }
        Err(_) => String::from_utf8_lossy(slice).into_owned(),
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

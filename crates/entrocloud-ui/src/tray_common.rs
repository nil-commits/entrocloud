//! Lightweight RGBA EntroCloud shield-cloud icon generator and human byte formatters
//! shared between `entrocloud` and `entrocloud-tray` (zero `eframe`/`egui` dependency).

/// Generates a crisp anti-aliased `width x height` RGBA procedural EntroCloud shield-cloud icon
/// (`#007D78` deep teal rounded badge, `#2DD4BF` highlight rim, and white cloud silhouette).
#[must_use]
pub fn generate_entrocloud_rgba_icon(width: u32, height: u32) -> Vec<u8> {
    let w = width.max(1);
    let h = height.max(1);
    let cap = (w as usize).saturating_mul(h as usize).saturating_mul(4);
    let mut rgba = Vec::with_capacity(cap);

    let wf = w as f32;
    let hf = h as f32;

    // 4x4 subpixel MSAA grid for smooth rounded corners and cloud curves.
    const SUB: usize = 4;
    let inv_sub = 1.0 / (SUB as f32);
    let total_samples = (SUB * SUB) as f32;

    for py in 0..h {
        for px in 0..w {
            let mut r_acc = 0.0f32;
            let mut g_acc = 0.0f32;
            let mut b_acc = 0.0f32;
            let mut a_acc = 0.0f32;

            for sy in 0..SUB {
                for sx in 0..SUB {
                    let u = ((px as f32) + ((sx as f32) + 0.5) * inv_sub) / wf;
                    let v = ((py as f32) + ((sy as f32) + 0.5) * inv_sub) / hf;

                    if let Some([sr, sg, sb]) = sample_brand_icon(u, v) {
                        r_acc += sr;
                        g_acc += sg;
                        b_acc += sb;
                        a_acc += 1.0;
                    }
                }
            }

            if a_acc <= 0.0 {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            } else {
                let coverage = a_acc / total_samples;
                let r = ((r_acc / a_acc).clamp(0.0, 255.0)).round() as u8;
                let g = ((g_acc / a_acc).clamp(0.0, 255.0)).round() as u8;
                let b = ((b_acc / a_acc).clamp(0.0, 255.0)).round() as u8;
                let a = ((coverage * 255.0).clamp(0.0, 255.0)).round() as u8;
                rgba.extend_from_slice(&[r, g, b, a]);
            }
        }
    }

    rgba
}

/// Backward-compatible alias for [`generate_entrocloud_rgba_icon`].
#[must_use]
pub fn generate_vault_rgba_icon(width: u32, height: u32) -> Vec<u8> {
    generate_entrocloud_rgba_icon(width, height)
}

fn sample_brand_icon(u: f32, v: f32) -> Option<[f32; 3]> {
    // Rounded squircle bounds in [0.06, 0.94] with corner radius 0.22.
    let dx = (u - 0.5).abs() - 0.22;
    let dy = (v - 0.5).abs() - 0.22;
    let qx = dx.max(0.0);
    let qy = dy.max(0.0);
    let sdf_box = (qx * qx + qy * qy).sqrt() + dx.min(dy).min(0.0) - 0.22;
    if sdf_box > 0.0 {
        return None;
    }

    // Subtle top-to-bottom teal gradient (#008A84 -> #132D37) with #2DD4BF inner rim.
    let t = v.clamp(0.0, 1.0);
    let mut bg = [
        lerp(0.0, 19.0, t * 0.55),
        lerp(132.0, 92.0, t * 0.65),
        lerp(126.0, 98.0, t * 0.60),
    ];

    if sdf_box > -0.042 {
        // Crisp mint-teal highlight rim (#2DD4BF) near top edge.
        let rim = (1.0 - v).clamp(0.15, 0.85) * 0.55;
        bg[0] = lerp(bg[0], 45.0, rim);
        bg[1] = lerp(bg[1], 212.0, rim);
        bg[2] = lerp(bg[2], 191.0, rim);
    }

    // Cloud silhouette composed of 3 circles + flat rounded base.
    let in_left = dist_sq(u, v, 0.34, 0.55) <= 0.125 * 0.125;
    let in_top = dist_sq(u, v, 0.49, 0.45) <= 0.165 * 0.165;
    let in_right = dist_sq(u, v, 0.66, 0.56) <= 0.115 * 0.115;
    let in_base = (0.33..=0.67).contains(&u) && (0.50..=0.675).contains(&v);
    let in_cloud = in_left || in_top || in_right || in_base;

    if in_cloud {
        // Small teal lock keyhole at the center of the white cloud for unmistakable privacy cue.
        let in_key_head = dist_sq(u, v, 0.50, 0.535) <= 0.042 * 0.042;
        let in_key_stem = (0.482..=0.518).contains(&u) && (0.535..=0.625).contains(&v);
        if in_key_head || in_key_stem {
            return Some([0.0, 118.0, 112.0]);
        }
        return Some([255.0, 255.0, 255.0]);
    }

    Some(bg)
}

fn dist_sq(x: f32, y: f32, cx: f32, cy: f32) -> f32 {
    let dx = x - cx;
    let dy = y - cy;
    dx * dx + dy * dy
}

fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
}

/// Formats a byte count using binary IEC units (`B`, `KiB`, `MiB`, `GiB`, `TiB`).
#[must_use]
pub fn format_bytes_iec(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    const TIB: f64 = GIB * 1024.0;

    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if b < MIB {
        format!("{:.2} KiB", b / KIB)
    } else if b < GIB {
        format!("{:.2} MiB", b / MIB)
    } else if b < TIB {
        format!("{:.2} GiB", b / GIB)
    } else {
        format!("{:.2} TiB", b / TIB)
    }
}

/// Formats a byte count with clean consumer-friendly units (`B`, `KB`, `MB`, `GB`, `TB`).
#[must_use]
pub fn format_bytes_human(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if b < MB {
        format!("{:.1} KB", b / KB)
    } else if b < GB {
        format!("{:.1} MB", b / MB)
    } else if b < TB {
        format!("{:.2} GB", b / GB)
    } else {
        format!("{:.2} TB", b / TB)
    }
}

/// Formats a byte-per-second throughput rate (e.g. `"42.80 MiB/s"`).
#[must_use]
pub fn format_rate_iec(bytes_per_sec: u64) -> String {
    format!("{}/s", format_bytes_iec(bytes_per_sec))
}

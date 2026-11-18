//! Typography, CloudBridge Light + Refined Dark palettes, persistent `UiPrefs`,
//! OS autostart registration, and polished reusable `egui` widgets.

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui::{
    self, Align2, Color32, CursorIcon, FontData, FontDefinitions, FontFamily, FontId, Margin,
    Pos2, Rect, Response, RichText, Rounding, Sense, Stroke, Vec2,
};
use serde::{Deserialize, Serialize};

use crate::icons::{Icon, paint_icon};

/// Named `egui::FontFamily` registered for Semibold headings, card titles, and buttons.
pub const SEMIBOLD_FAMILY_NAME: &str = "Semibold";

/// User-selectable color theme mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemePreference {
    /// CloudBridge calm light palette (`#132D37` sidebar, `#F4F7F8` canvas, `#FFFFFF` cards).
    #[default]
    Light,
    /// Refined dark palette (`#0B1922` sidebar, `#0F171E` canvas, `#16222C` cards).
    Dark,
    /// Automatically follow the operating system Light / Dark mode.
    System,
}

/// Persistent desktop UI preferences saved in `%LOCALAPPDATA%\EntroCloud\ui_prefs.json`
/// on Windows or `~/.config/entrocloud/ui_prefs.json` on Linux.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiPrefs {
    /// Selected color theme (`Light`, `Dark`, `System`).
    #[serde(default)]
    pub theme: ThemePreference,
    /// Whether the 4-step first-run onboarding wizard has been completed or dismissed.
    #[serde(default)]
    pub wizard_completed: bool,
    /// `true` for visual Grid View in `My Files`, `false` for table List View.
    #[serde(default = "default_true")]
    pub file_view_grid: bool,
    /// Whether EntroCloud is registered to start automatically when signing in to the OS.
    #[serde(default)]
    pub start_with_os: bool,
}

fn default_true() -> bool {
    true
}

impl Default for UiPrefs {
    fn default() -> Self {
        Self {
            theme: ThemePreference::Light,
            wizard_completed: false,
            file_view_grid: true,
            start_with_os: false,
        }
    }
}

impl UiPrefs {
    /// Returns the platform-specific `ui_prefs.json` path.
    #[must_use]
    pub fn default_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            let base = dirs::data_local_dir()
                .or_else(dirs::home_dir)
                .unwrap_or_else(std::env::temp_dir);
            base.join("EntroCloud").join("ui_prefs.json")
        }
        #[cfg(not(target_os = "windows"))]
        {
            let base = dirs::config_dir()
                .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
                .unwrap_or_else(std::env::temp_dir);
            base.join("entrocloud").join("ui_prefs.json")
        }
    }

    /// Loads `UiPrefs` from disk, falling back cleanly to `Self::default()` if absent or malformed.
    #[must_use]
    pub fn load() -> Self {
        let path = Self::default_path();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str::<Self>(&raw).ok())
            .unwrap_or_default()
    }

    /// Saves `UiPrefs` atomically/cleanly to disk.
    pub fn save(&self) -> Result<(), String> {
        let path = Self::default_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed creating preferences folder: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed serializing UI preferences: {e}"))?;
        std::fs::write(&path, json).map_err(|e| format!("Failed saving UI preferences: {e}"))
    }
}

/// Loads real OS TrueType fonts (`Segoe UI` Regular & Semibold + `Consolas` on Windows;
/// `DejaVu Sans` / `Noto Sans` / `Cantarell` on Linux) when present on disk, and ALWAYS
/// registers the `"Semibold"` named font family so `semibold_font()` never fails.
pub fn install_os_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    let mut proportional_loaded = false;
    let mut semibold_loaded = false;

    #[cfg(target_os = "windows")]
    {
        if let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\segoeui.ttf") {
            fonts
                .font_data
                .insert("os_regular".to_owned(), FontData::from_owned(bytes));
            if let Some(fam) = fonts.families.get_mut(&FontFamily::Proportional) {
                fam.insert(0, "os_regular".to_owned());
            }
            proportional_loaded = true;
        }
        if let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\seguisb.ttf") {
            fonts
                .font_data
                .insert("os_semibold".to_owned(), FontData::from_owned(bytes));
            semibold_loaded = true;
        }
        if let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\consola.ttf") {
            fonts
                .font_data
                .insert("os_mono".to_owned(), FontData::from_owned(bytes));
            if let Some(fam) = fonts.families.get_mut(&FontFamily::Monospace) {
                fam.insert(0, "os_mono".to_owned());
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let user_fonts_dir = dirs::data_local_dir()
            .map(|d| d.join("fonts"))
            .or_else(|| dirs::home_dir().map(|h| h.join(".local/share/fonts")));

        let load_first = |system_paths: &[&str], user_rel_paths: &[&str]| -> Option<Vec<u8>> {
            if let Some(ref udir) = user_fonts_dir {
                for rel in user_rel_paths {
                    if let Ok(bytes) = std::fs::read(udir.join(rel)) {
                        return Some(bytes);
                    }
                }
            }
            for path in system_paths {
                if let Ok(bytes) = std::fs::read(path) {
                    return Some(bytes);
                }
            }
            None
        };

        let regular_user = [
            "Inter-Regular.ttf",
            "Inter-Regular.otf",
            "inter/Inter-Regular.ttf",
            "SF-Pro-Text-Regular.otf",
            "SFProText-Regular.ttf",
            "NotoSans-Regular.ttf",
        ];
        let regular_system = [
            // Inter (Ubuntu, Arch, Fedora)
            "/usr/share/fonts/inter/Inter-Regular.ttf",
            "/usr/share/fonts/inter/Inter-Regular.otf",
            "/usr/share/fonts/TTF/Inter-Regular.ttf",
            "/usr/share/fonts/OTF/Inter-Regular.otf",
            "/usr/share/fonts/truetype/inter/Inter-Regular.ttf",
            "/usr/share/fonts/opentype/inter/Inter-Regular.otf",
            "/usr/share/fonts/inter-fonts/Inter-Regular.ttf",
            // Cantarell / Adwaita Sans (GNOME / Fedora / Arch)
            "/usr/share/fonts/cantarell/Cantarell-Regular.otf",
            "/usr/share/fonts/opentype/cantarell/Cantarell-Regular.otf",
            "/usr/share/fonts/abattis-cantarell-fonts/Cantarell-Regular.otf",
            "/usr/share/fonts/adwaita-sans-fonts/AdwaitaSans-Regular.ttf",
            "/usr/share/fonts/TTF/AdwaitaSans-Regular.ttf",
            // Ubuntu Sans (Ubuntu)
            "/usr/share/fonts/truetype/ubuntu/UbuntuSans-Regular.ttf",
            "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
            "/usr/share/fonts/ubuntu/Ubuntu-R.ttf",
            // Noto Sans (KDE Plasma / Arch / Fedora / Ubuntu)
            "/usr/share/fonts/noto/NotoSans-Regular.ttf",
            "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
            "/usr/share/fonts/google-noto/NotoSans-Regular.ttf",
            "/usr/share/fonts/google-noto-vf/NotoSans[wght].ttf",
            // Liberation Sans & DejaVu Sans (universal Linux fallbacks)
            "/usr/share/fonts/TTF/LiberationSans-Regular.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
            "/usr/share/fonts/liberation-sans/LiberationSans-Regular.ttf",
            "/usr/share/fonts/TTF/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf",
        ];
        if let Some(bytes) = load_first(&regular_system, &regular_user) {
            fonts
                .font_data
                .insert("os_regular".to_owned(), FontData::from_owned(bytes));
            if let Some(fam) = fonts.families.get_mut(&FontFamily::Proportional) {
                fam.insert(0, "os_regular".to_owned());
            }
            proportional_loaded = true;
        }

        let semibold_user = [
            "Inter-SemiBold.ttf",
            "Inter-SemiBold.otf",
            "Inter-Medium.ttf",
            "inter/Inter-SemiBold.ttf",
            "SF-Pro-Text-Semibold.otf",
            "SFProText-Semibold.ttf",
            "NotoSans-SemiBold.ttf",
        ];
        let semibold_system = [
            // Inter SemiBold / Medium
            "/usr/share/fonts/inter/Inter-SemiBold.ttf",
            "/usr/share/fonts/inter/Inter-SemiBold.otf",
            "/usr/share/fonts/inter/Inter-Medium.ttf",
            "/usr/share/fonts/TTF/Inter-SemiBold.ttf",
            "/usr/share/fonts/OTF/Inter-SemiBold.otf",
            "/usr/share/fonts/truetype/inter/Inter-SemiBold.ttf",
            "/usr/share/fonts/opentype/inter/Inter-SemiBold.otf",
            "/usr/share/fonts/inter-fonts/Inter-SemiBold.ttf",
            // Cantarell / Adwaita Sans
            "/usr/share/fonts/cantarell/Cantarell-Bold.otf",
            "/usr/share/fonts/opentype/cantarell/Cantarell-Bold.otf",
            "/usr/share/fonts/abattis-cantarell-fonts/Cantarell-Bold.otf",
            "/usr/share/fonts/adwaita-sans-fonts/AdwaitaSans-SemiBold.ttf",
            "/usr/share/fonts/adwaita-sans-fonts/AdwaitaSans-Bold.ttf",
            // Ubuntu Medium / Bold
            "/usr/share/fonts/truetype/ubuntu/UbuntuSans-SemiBold.ttf",
            "/usr/share/fonts/truetype/ubuntu/UbuntuSans-Medium.ttf",
            "/usr/share/fonts/truetype/ubuntu/Ubuntu-M.ttf",
            "/usr/share/fonts/truetype/ubuntu/Ubuntu-B.ttf",
            "/usr/share/fonts/ubuntu/Ubuntu-M.ttf",
            // Noto Sans SemiBold / Medium / Bold
            "/usr/share/fonts/noto/NotoSans-SemiBold.ttf",
            "/usr/share/fonts/noto/NotoSans-Medium.ttf",
            "/usr/share/fonts/noto/NotoSans-Bold.ttf",
            "/usr/share/fonts/truetype/noto/NotoSans-SemiBold.ttf",
            "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
            "/usr/share/fonts/google-noto/NotoSans-SemiBold.ttf",
            "/usr/share/fonts/google-noto/NotoSans-Bold.ttf",
            // Liberation Sans & DejaVu Sans Bold
            "/usr/share/fonts/TTF/LiberationSans-Bold.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
            "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf",
            "/usr/share/fonts/liberation-sans/LiberationSans-Bold.ttf",
            "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans-Bold.ttf",
        ];
        if let Some(bytes) = load_first(&semibold_system, &semibold_user) {
            fonts
                .font_data
                .insert("os_semibold".to_owned(), FontData::from_owned(bytes));
            semibold_loaded = true;
        }

        let mono_user = [
            "JetBrainsMono-Regular.ttf",
            "jetbrains-mono/JetBrainsMono-Regular.ttf",
            "SFMono-Regular.otf",
            "NotoSansMono-Regular.ttf",
        ];
        let mono_system = [
            "/usr/share/fonts/TTF/JetBrainsMono-Regular.ttf",
            "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf",
            "/usr/share/fonts/jetbrains-mono-fonts/JetBrainsMono-Regular.ttf",
            "/usr/share/fonts/noto/NotoSansMono-Regular.ttf",
            "/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
            "/usr/share/fonts/google-noto/NotoSansMono-Regular.ttf",
            "/usr/share/fonts/truetype/ubuntu/UbuntuSansMono-Regular.ttf",
            "/usr/share/fonts/truetype/ubuntu/UbuntuMono-R.ttf",
            "/usr/share/fonts/TTF/LiberationMono-Regular.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
            "/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf",
            "/usr/share/fonts/liberation-mono/LiberationMono-Regular.ttf",
            "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/dejavu-sans-mono-fonts/DejaVuSansMono.ttf",
        ];
        if let Some(bytes) = load_first(&mono_system, &mono_user) {
            fonts
                .font_data
                .insert("os_mono".to_owned(), FontData::from_owned(bytes));
            if let Some(fam) = fonts.families.get_mut(&FontFamily::Monospace) {
                fam.insert(0, "os_mono".to_owned());
            }
        }
    }

    let mut semibold_chain: Vec<String> = Vec::new();
    if semibold_loaded {
        semibold_chain.push("os_semibold".to_owned());
    } else if proportional_loaded {
        semibold_chain.push("os_regular".to_owned());
    }
    if let Some(existing_prop) = fonts.families.get(&FontFamily::Proportional) {
        for name in existing_prop {
            if !semibold_chain.iter().any(|n| n == name) {
                semibold_chain.push(name.clone());
            }
        }
    }
    fonts.families.insert(
        FontFamily::Name(Arc::from(SEMIBOLD_FAMILY_NAME)),
        semibold_chain,
    );

    ctx.set_fonts(fonts);
}

/// Returns a `FontId` using the Semibold OS font family if installed on `ctx`, falling back safely
/// to `FontFamily::Proportional` when running in raw uninitialized test contexts.
#[must_use]
pub fn semibold_font(ctx: &egui::Context, size: f32) -> FontId {
    let has_semibold = ctx.fonts(|f| {
        f.families()
            .iter()
            .any(|fam| matches!(fam, FontFamily::Name(n) if n.as_ref() == SEMIBOLD_FAMILY_NAME))
    });
    if has_semibold {
        FontId::new(size, FontFamily::Name(Arc::from(SEMIBOLD_FAMILY_NAME)))
    } else {
        FontId::proportional(size)
    }
}

/// Semantic pill tone for status indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PillTone {
    Ok,
    Accent,
    Warn,
    Danger,
    Neutral,
}

/// Complete resolved color palette for either CloudBridge Light or Refined Dark mode.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub is_dark: bool,
    pub sidebar_bg: Color32,
    pub sidebar_active_bg: Color32,
    pub sidebar_hover_bg: Color32,
    pub sidebar_accent: Color32,
    pub sidebar_text: Color32,
    pub sidebar_inactive_text: Color32,
    pub sidebar_muted: Color32,
    pub sidebar_border: Color32,

    pub canvas_bg: Color32,
    pub topbar_bg: Color32,
    pub card_bg: Color32,
    pub card_sub_bg: Color32,
    pub card_border: Color32,
    pub input_bg: Color32,
    pub input_border: Color32,

    pub ink: Color32,
    pub muted: Color32,

    pub primary_btn: Color32,
    pub primary_btn_hover: Color32,
    pub primary_btn_text: Color32,

    pub secondary_btn: Color32,
    pub secondary_btn_hover: Color32,
    pub secondary_btn_border: Color32,

    pub danger_bg: Color32,
    pub danger_hover: Color32,
    pub danger_border: Color32,
    pub danger_fg: Color32,

    pub ok_bg: Color32,
    pub ok_fg: Color32,
    pub warn_bg: Color32,
    pub warn_fg: Color32,
    pub accent_soft_bg: Color32,
    pub accent_soft_fg: Color32,
    pub progress_track: Color32,
}

impl Palette {
    /// CloudBridge Light Palette (`#132D37` sidebar, `#F4F7F8` canvas, `#FFFFFF` cards, `#007D78` primary teal).
    #[must_use]
    pub const fn light() -> Self {
        Self {
            is_dark: false,
            sidebar_bg: Color32::from_rgb(0x13, 0x2D, 0x37),
            sidebar_active_bg: Color32::from_rgb(0x24, 0x45, 0x50),
            sidebar_hover_bg: Color32::from_rgb(0x1B, 0x3A, 0x45),
            sidebar_accent: Color32::from_rgb(0x2D, 0xD4, 0xBF),
            sidebar_text: Color32::from_rgb(0xFF, 0xFF, 0xFF),
            sidebar_inactive_text: Color32::from_rgb(0xD7, 0xE8, 0xEC),
            sidebar_muted: Color32::from_rgb(0x8E, 0xB4, 0xBC),
            sidebar_border: Color32::from_rgb(0x2B, 0x4C, 0x58),

            canvas_bg: Color32::from_rgb(0xF4, 0xF7, 0xF8),
            topbar_bg: Color32::from_rgb(0xFF, 0xFF, 0xFF),
            card_bg: Color32::from_rgb(0xFF, 0xFF, 0xFF),
            card_sub_bg: Color32::from_rgb(0xF7, 0xFA, 0xFB),
            card_border: Color32::from_rgb(0xE6, 0xED, 0xF0),
            input_bg: Color32::from_rgb(0xFF, 0xFF, 0xFF),
            input_border: Color32::from_rgb(0xCE, 0xDA, 0xDF),

            ink: Color32::from_rgb(0x17, 0x2B, 0x39),
            muted: Color32::from_rgb(0x64, 0x77, 0x84),

            primary_btn: Color32::from_rgb(0x00, 0x7D, 0x78),
            primary_btn_hover: Color32::from_rgb(0x00, 0x66, 0x62),
            primary_btn_text: Color32::from_rgb(0xFF, 0xFF, 0xFF),

            secondary_btn: Color32::from_rgb(0xFF, 0xFF, 0xFF),
            secondary_btn_hover: Color32::from_rgb(0xED, 0xF3, 0xF5),
            secondary_btn_border: Color32::from_rgb(0xD8, 0xE2, 0xE5),

            danger_bg: Color32::from_rgb(0xFE, 0xF2, 0xF2),
            danger_hover: Color32::from_rgb(0xFE, 0xE2, 0xE2),
            danger_border: Color32::from_rgb(0xFE, 0xCA, 0xCA),
            danger_fg: Color32::from_rgb(0xB9, 0x1C, 0x1C),

            ok_bg: Color32::from_rgb(0xE6, 0xF6, 0xF4),
            ok_fg: Color32::from_rgb(0x00, 0x69, 0x64),
            warn_bg: Color32::from_rgb(0xFE, 0xF6, 0xE6),
            warn_fg: Color32::from_rgb(0x9A, 0x67, 0x00),
            accent_soft_bg: Color32::from_rgb(0xE8, 0xF5, 0xF4),
            accent_soft_fg: Color32::from_rgb(0x00, 0x7D, 0x78),
            progress_track: Color32::from_rgb(0xE5, 0xEF, 0xF0),
        }
    }

    /// Refined Dark Palette (`#0B1922` sidebar, `#0F171E` canvas, `#16222C` cards, `#0D9488` primary teal).
    #[must_use]
    pub const fn dark() -> Self {
        Self {
            is_dark: true,
            sidebar_bg: Color32::from_rgb(0x0B, 0x19, 0x22),
            sidebar_active_bg: Color32::from_rgb(0x16, 0x30, 0x3D),
            sidebar_hover_bg: Color32::from_rgb(0x10, 0x24, 0x30),
            sidebar_accent: Color32::from_rgb(0x2D, 0xD4, 0xBF),
            sidebar_text: Color32::from_rgb(0xFF, 0xFF, 0xFF),
            sidebar_inactive_text: Color32::from_rgb(0xD7, 0xE8, 0xEC),
            sidebar_muted: Color32::from_rgb(0x8E, 0xB4, 0xBC),
            sidebar_border: Color32::from_rgb(0x1E, 0x38, 0x47),

            canvas_bg: Color32::from_rgb(0x0F, 0x17, 0x1E),
            topbar_bg: Color32::from_rgb(0x13, 0x1E, 0x27),
            card_bg: Color32::from_rgb(0x16, 0x22, 0x2C),
            card_sub_bg: Color32::from_rgb(0x1B, 0x2A, 0x36),
            card_border: Color32::from_rgb(0x20, 0x30, 0x3D),
            input_bg: Color32::from_rgb(0x11, 0x1B, 0x24),
            input_border: Color32::from_rgb(0x2E, 0x43, 0x54),

            ink: Color32::from_rgb(0xEE, 0xF5, 0xF8),
            muted: Color32::from_rgb(0x8C, 0xA3, 0xB0),

            primary_btn: Color32::from_rgb(0x0D, 0x94, 0x88),
            primary_btn_hover: Color32::from_rgb(0x14, 0xB8, 0xA6),
            primary_btn_text: Color32::from_rgb(0xFF, 0xFF, 0xFF),

            secondary_btn: Color32::from_rgb(0x1E, 0x2D, 0x3A),
            secondary_btn_hover: Color32::from_rgb(0x26, 0x39, 0x49),
            secondary_btn_border: Color32::from_rgb(0x2E, 0x43, 0x54),

            danger_bg: Color32::from_rgb(0x2E, 0x16, 0x19),
            danger_hover: Color32::from_rgb(0x3D, 0x1D, 0x21),
            danger_border: Color32::from_rgb(0x5E, 0x26, 0x2B),
            danger_fg: Color32::from_rgb(0xFC, 0xA5, 0xA5),

            ok_bg: Color32::from_rgb(0x10, 0x33, 0x30),
            ok_fg: Color32::from_rgb(0x2D, 0xD4, 0xBF),
            warn_bg: Color32::from_rgb(0x33, 0x26, 0x10),
            warn_fg: Color32::from_rgb(0xFB, 0xBF, 0x24),
            accent_soft_bg: Color32::from_rgb(0x12, 0x31, 0x39),
            accent_soft_fg: Color32::from_rgb(0x2D, 0xD4, 0xBF),
            progress_track: Color32::from_rgb(0x20, 0x31, 0x3E),
        }
    }

    /// Resolves the active [`Palette`] for `pref` given the current `egui::Context` / OS system theme.
    #[must_use]
    pub fn resolve(pref: ThemePreference, ctx: &egui::Context) -> Self {
        match pref {
            ThemePreference::Light => Self::light(),
            ThemePreference::Dark => Self::dark(),
            ThemePreference::System => {
                if let Some(theme) = ctx.system_theme() {
                    match theme {
                        egui::Theme::Dark => Self::dark(),
                        egui::Theme::Light => Self::light(),
                    }
                } else if detect_os_dark_mode() {
                    Self::dark()
                } else {
                    Self::light()
                }
            }
        }
    }
}

fn detect_os_dark_mode() -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::Registry::{
            HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW,
        };
        let mut val: u32 = 1;
        let mut size = std::mem::size_of::<u32>() as u32;
        // SAFETY: Reads a single DWORD from `HKCU\...\Personalize` into a stack `u32`.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                windows::core::w!(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"),
                windows::core::w!("AppsUseLightTheme"),
                RRF_RT_REG_DWORD,
                None,
                Some((&raw mut val).cast()),
                Some(&raw mut size),
            )
        };
        status.is_ok() && val == 0
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(gtk_theme) = std::env::var("GTK_THEME")
            && gtk_theme.to_ascii_lowercase().contains("dark")
        {
            return true;
        }
        if let Some(cfg_dir) = dirs::config_dir()
            && let Ok(kdeglobals) = std::fs::read_to_string(cfg_dir.join("kdeglobals"))
        {
            for line in kdeglobals.lines() {
                if let Some(scheme) = line.trim().strip_prefix("ColorScheme=")
                    && scheme.to_ascii_lowercase().contains("dark")
                {
                    return true;
                }
            }
        }
        false
    }
}

/// Applies the resolved [`Palette`] to `egui::Visuals` & `egui::Style` so text inputs, checkboxes,
/// scrollbars, combo boxes, and modals match the exact CloudBridge Light / Refined Dark design.
pub fn apply_palette(ctx: &egui::Context, pal: &Palette) {
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = Vec2::new(8.0, 8.0);
    style.spacing.button_padding = Vec2::new(12.0, 7.0);
    style.spacing.window_margin = Margin::same(20.0);
    style.spacing.scroll = egui::style::ScrollStyle::floating();

    let mut visuals = if pal.is_dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };

    visuals.override_text_color = Some(pal.ink);
    visuals.panel_fill = pal.canvas_bg;
    visuals.window_fill = pal.card_bg;
    visuals.window_stroke = Stroke::new(1.0, pal.card_border);
    visuals.window_rounding = Rounding::same(14.0);
    visuals.extreme_bg_color = pal.input_bg;
    visuals.faint_bg_color = pal.card_sub_bg;

    let hover_input_border = pal
        .input_border
        .gamma_multiply(if pal.is_dark { 1.18 } else { 0.85 });

    visuals.widgets.noninteractive.bg_fill = pal.card_bg;
    visuals.widgets.noninteractive.weak_bg_fill = pal.card_sub_bg;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, pal.card_border);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, pal.ink);
    visuals.widgets.noninteractive.rounding = Rounding::same(8.0);

    visuals.widgets.inactive.bg_fill = pal.input_bg;
    visuals.widgets.inactive.weak_bg_fill = pal.secondary_btn;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, pal.input_border);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.2, pal.ink);
    visuals.widgets.inactive.rounding = Rounding::same(8.0);

    visuals.widgets.hovered.bg_fill = pal.secondary_btn_hover;
    visuals.widgets.hovered.weak_bg_fill = pal.secondary_btn_hover;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, hover_input_border);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.4, pal.ink);
    visuals.widgets.hovered.rounding = Rounding::same(8.0);

    visuals.widgets.active.bg_fill = pal.primary_btn;
    visuals.widgets.active.weak_bg_fill = pal.primary_btn;
    visuals.widgets.active.bg_stroke = Stroke::new(1.2, pal.primary_btn);
    visuals.widgets.active.fg_stroke = Stroke::new(1.5, pal.primary_btn_text);
    visuals.widgets.active.rounding = Rounding::same(8.0);

    visuals.widgets.open.bg_fill = pal.card_bg;
    visuals.widgets.open.weak_bg_fill = pal.card_sub_bg;
    visuals.widgets.open.bg_stroke = Stroke::new(1.2, pal.primary_btn);
    visuals.widgets.open.fg_stroke = Stroke::new(1.3, pal.ink);
    visuals.widgets.open.rounding = Rounding::same(8.0);

    visuals.window_shadow = egui::epaint::Shadow {
        offset: Vec2::new(0.0, 8.0),
        blur: 24.0,
        spread: 0.0,
        color: Color32::from_black_alpha(if pal.is_dark { 110 } else { 42 }),
    };
    visuals.popup_shadow = egui::epaint::Shadow {
        offset: Vec2::new(0.0, 4.0),
        blur: 14.0,
        spread: 0.0,
        color: Color32::from_black_alpha(if pal.is_dark { 96 } else { 32 }),
    };

    visuals.selection.bg_fill = pal.primary_btn.gamma_multiply(if pal.is_dark { 0.45 } else { 0.22 });
    visuals.selection.stroke = Stroke::new(1.5, pal.primary_btn);
    visuals.hyperlink_color = pal.primary_btn;

    style.visuals = visuals;
    ctx.set_style(style);
}

/// Registers or removes EntroCloud in the OS login startup list:
/// - Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` -> `"EntroCloud"`
/// - Linux: `~/.config/autostart/entrocloud.desktop`
pub fn set_os_autostart_enabled(enabled: bool) -> Result<(), String> {
    let cur_exe = std::env::current_exe()
        .map_err(|e| format!("Could not resolve current executable path: {e}"))?;
    // Prefer launching the ultra-lightweight tray companion at login when installed side-by-side,
    // falling back cleanly to the main `entrocloud` executable.
    let target_exe = cur_exe
        .parent()
        .and_then(|dir| crate::ipc_client::locate_executable_in_dir(dir, "entrocloud-tray"))
        .unwrap_or(cur_exe);

    #[cfg(target_os = "windows")]
    {
        use widestring::U16CString;
        use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
        use windows::Win32::System::Registry::{
            HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
            RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegSetValueExW,
        };
        use windows::core::PCWSTR;

        let mut hkey = HKEY::default();
        // SAFETY: Opens/creates the current user's standard `Run` key with `KEY_SET_VALUE` access.
        let open_status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                windows::core::w!(r"Software\Microsoft\Windows\CurrentVersion\Run"),
                Some(0),
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                None,
                &raw mut hkey,
                None,
            )
        };
        if open_status.is_err() {
            return Err(format!(
                "Could not open Windows startup registry key: {open_status:?}"
            ));
        }

        let result = if enabled {
            let quoted = format!("\"{}\"", target_exe.display());
            let wide = U16CString::from_str(&quoted)
                .map_err(|e| format!("Invalid startup executable path: {e}"))?;
            let slice_u16 = wide.as_slice_with_nul();
            // SAFETY: Reinterprets valid UTF-16 slice (including terminating NUL) as raw bytes for `REG_SZ`.
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    slice_u16.as_ptr().cast::<u8>(),
                    std::mem::size_of_val(slice_u16),
                )
            };
            // SAFETY: `hkey` is open and `bytes` points to valid null-terminated UTF-16 bytes.
            let set_res = unsafe {
                RegSetValueExW(
                    hkey,
                    windows::core::w!("EntroCloud"),
                    Some(0),
                    REG_SZ,
                    Some(bytes),
                )
            };
            if set_res.is_err() {
                Err(format!("Failed writing Windows startup entry: {set_res:?}"))
            } else {
                Ok(())
            }
        } else {
            // SAFETY: `hkey` is open; deleting absent value is treated as idempotent success.
            let del_res = unsafe { RegDeleteValueW(hkey, windows::core::w!("EntroCloud")) };
            if del_res.is_err() && del_res != ERROR_FILE_NOT_FOUND {
                Err(format!(
                    "Failed removing Windows startup entry: {del_res:?}"
                ))
            } else {
                Ok(())
            }
        };

        // SAFETY: Closes handle opened by `RegCreateKeyExW`.
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        result
    }

    #[cfg(not(target_os = "windows"))]
    {
        let autostart_dir = dirs::config_dir()
            .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
            .unwrap_or_else(std::env::temp_dir)
            .join("autostart");
        let desktop_file = autostart_dir.join("entrocloud.desktop");

        if enabled {
            std::fs::create_dir_all(&autostart_dir)
                .map_err(|e| format!("Failed creating autostart folder: {e}"))?;
            let exe_str = target_exe.display().to_string();
            let escaped_exec = escape_desktop_exec_arg(&exe_str);
            let content = format!(
                "[Desktop Entry]\nType=Application\nName=EntroCloud\nComment=Private Cloud Backup & Encrypted Drive\nIcon=entrocloud\nExec=\"{escaped_exec}\"\nTerminal=false\nStartupNotify=false\nCategories=Utility;Network;FileTools;\nX-GNOME-Autostart-enabled=true\n"
            );
            std::fs::write(&desktop_file, content)
                .map_err(|e| format!("Failed writing autostart entry: {e}"))
        } else {
            match std::fs::remove_file(&desktop_file) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(format!("Failed removing autostart entry: {e}")),
            }
        }
    }
}

/// Escapes an executable path for placement inside double quotes in an XDG `.desktop` `Exec=` key
/// per the freedesktop Desktop Entry Specification (`\`, `"`, `` ` ``, `$`, and `%` -> `%%`).
#[must_use]
pub fn escape_desktop_exec_arg(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' | '"' | '`' | '$' => {
                out.push('\\');
                out.push(ch);
            }
            '%' => {
                out.push_str("%%");
            }
            other => out.push(other),
        }
    }
    out
}

// =========================================================================
// REUSABLE POLISHED UI COMPONENTS
// =========================================================================

fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let inv = 1.0 - t;
    let [ar, ag, ab, aa] = a.to_array();
    let [br, bg, bb, ba] = b.to_array();
    Color32::from_rgba_premultiplied(
        (f32::from(ar) * inv + f32::from(br) * t).round() as u8,
        (f32::from(ag) * inv + f32::from(bg) * t).round() as u8,
        (f32::from(ab) * inv + f32::from(bb) * t).round() as u8,
        (f32::from(aa) * inv + f32::from(ba) * t).round() as u8,
    )
}

fn darken_pressed(color: Color32, pressed: bool) -> Color32 {
    if pressed {
        color.gamma_multiply(0.93)
    } else {
        color
    }
}

fn card_elevation_shadow(pal: &Palette) -> egui::epaint::Shadow {
    egui::epaint::Shadow {
        offset: Vec2::new(0.0, 1.5),
        blur: 8.0,
        spread: 0.0,
        color: Color32::from_black_alpha(if pal.is_dark { 36 } else { 10 }),
    }
}

/// Standard CloudBridge card (`#FFFFFF` / `#16222C`, softened `1px` border, `12px` rounding, `22px` padding, whisper elevation).
pub fn card_frame(pal: &Palette) -> egui::Frame {
    egui::Frame::none()
        .fill(pal.card_bg)
        .stroke(Stroke::new(1.0, pal.card_border))
        .rounding(Rounding::same(12.0))
        .inner_margin(Margin::same(22.0))
        .shadow(card_elevation_shadow(pal))
}

/// Compact card frame with custom padding (`12px` rounding and whisper elevation).
pub fn compact_card_frame(pal: &Palette, pad_x: f32, pad_y: f32) -> egui::Frame {
    egui::Frame::none()
        .fill(pal.card_bg)
        .stroke(Stroke::new(1.0, pal.card_border))
        .rounding(Rounding::same(12.0))
        .inner_margin(Margin::symmetric(pad_x, pad_y))
        .shadow(card_elevation_shadow(pal))
}

/// Subtle inset container inside a card (`card_sub_bg`, `8px` rounding).
pub fn sub_card_frame(pal: &Palette) -> egui::Frame {
    egui::Frame::none()
        .fill(pal.card_sub_bg)
        .stroke(Stroke::new(1.0, pal.card_border))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::symmetric(14.0, 12.0))
}

/// Form field label in crisp Semibold ink.
pub fn form_label(ui: &mut egui::Ui, pal: &Palette, text: &str) {
    let font = semibold_font(ui.ctx(), 13.0);
    ui.label(RichText::new(text).font(font).color(pal.ink));
}

/// Consistent full-width single-line `TextEdit` with balanced vertical padding matching action buttons.
pub fn text_input_single<'a>(text: &'a mut String, hint: &'a str) -> egui::TextEdit<'a> {
    egui::TextEdit::singleline(text)
        .margin(Margin::symmetric(10.0, 7.5))
        .desired_width(f32::INFINITY)
        .hint_text(hint)
}

/// Lays out `[Left flexible widget (fills exact remaining width)]  [Right button/widget]`
/// with zero hardcoded pixel subtractions and zero horizontal overflow on any font or DPI.
pub fn input_row_with_right_widget<R>(
    ui: &mut egui::Ui,
    right_widget: impl FnOnce(&mut egui::Ui) -> R,
    left_widget: impl FnOnce(&mut egui::Ui, f32),
) -> R {
    let total_w = ui.available_width().max(120.0);
    let row_h = 36.0;
    let inner = ui.allocate_ui_with_layout(
        Vec2::new(total_w, row_h),
        egui::Layout::right_to_left(egui::Align::Center),
        |ui| {
            let out = right_widget(ui);
            let rem_w = ui.available_width().max(48.0);
            ui.allocate_ui_with_layout(
                Vec2::new(rem_w, row_h),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    left_widget(ui, rem_w);
                },
            );
            out
        },
    );
    inner.inner
}

/// Clickable choice / provider / policy card whose height expands automatically when text wraps
/// on narrow windows or HiDPI scaling so labels never overflow bottom card borders.
pub fn interactive_card(
    ui: &mut egui::Ui,
    pal: &Palette,
    selected: bool,
    min_height: f32,
    pad: Vec2,
    rounding: f32,
    add_contents: impl FnOnce(&mut egui::Ui),
) -> Response {
    let full_w = ui.available_width().max(80.0);
    let bg_slot = ui.painter().add(egui::Shape::Noop);
    let inner_resp = ui.scope_builder(egui::UiBuilder::new().sense(Sense::click()), |ui| {
        egui::Frame::none()
            .inner_margin(Margin::symmetric(pad.x, pad.y))
            .show(ui, |ui| {
                let inner_w = (full_w - pad.x * 2.0).max(40.0);
                ui.set_min_width(inner_w);
                ui.set_max_width(inner_w);
                if min_height > pad.y * 2.0 {
                    ui.set_min_height(min_height - pad.y * 2.0);
                }
                add_contents(ui);
            });
    });
    let resp = inner_resp.response;
    if resp.hovered() && ui.is_enabled() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
    if ui.is_rect_visible(resp.rect) {
        let enabled = ui.is_enabled();
        let hover_t = ui
            .ctx()
            .animate_bool_with_time(resp.id, resp.hovered() && enabled, 0.12);
        let pressed = resp.is_pointer_button_down_on() && enabled;
        let (bg, border, bw) = if selected {
            (
                darken_pressed(pal.accent_soft_bg, pressed),
                pal.primary_btn,
                1.8,
            )
        } else {
            (
                darken_pressed(
                    lerp_color(pal.card_sub_bg, pal.secondary_btn_hover, hover_t),
                    pressed,
                ),
                lerp_color(
                    pal.card_border,
                    pal.primary_btn.gamma_multiply(0.60),
                    hover_t,
                ),
                1.0 + 0.2 * hover_t,
            )
        };
        let r = Rounding::same(rounding);
        ui.painter().set(
            bg_slot,
            egui::Shape::Vec(vec![
                egui::Shape::rect_filled(resp.rect, r, bg),
                egui::Shape::rect_stroke(resp.rect, r, Stroke::new(bw, border)),
            ]),
        );
    }
    resp
}

/// Renders a centered, strictly width-bounded modal dialog over a dimmed full-window backdrop scrim.
///
/// Guarantees that inner `desired_width(f32::INFINITY)`, `ui.columns(...)`, and `Layout::right_to_left`
/// rows stay locked to `target_width` (clamped safely to the viewport) with zero multi-frame inflation,
/// zero ugly default `egui::Window` gray titlebars, `Escape`-to-close, and vertical scroll fallback on
/// short viewports. Returns the outer modal card `Rect` once shown.
pub fn modal_dialog<R>(
    ctx: &egui::Context,
    pal: &Palette,
    id_salt: &'static str,
    title: &str,
    target_width: f32,
    close_requested: &mut bool,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> Option<(R, Rect)> {
    if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        *close_requested = true;
    }

    let screen = ctx.screen_rect();

    // 1. Full-window dimmed modal scrim that blocks background interactions
    egui::Area::new(egui::Id::new((id_salt, "modal_scrim")))
        .order(egui::Order::Middle)
        .fixed_pos(screen.min)
        .movable(false)
        .fade_in(false)
        .show(ctx, |ui| {
            let (rect, _) = ui.allocate_exact_size(screen.size(), Sense::click_and_drag());
            let alpha = if pal.is_dark { 130 } else { 76 };
            ui.painter()
                .rect_filled(rect, Rounding::ZERO, Color32::from_black_alpha(alpha));
        });

    // 2. Strictly bounded centered modal card
    let margin_px = 22.0;
    let max_outer_w = (screen.width() - 48.0).max(260.0);
    let inner_w = target_width
        .min(max_outer_w - margin_px * 2.0)
        .max(216.0);
    let max_inner_h = (screen.height() - 64.0 - margin_px * 2.0).max(180.0);
    let max_scroll_h = (max_inner_h - 56.0).max(120.0);

    let modal_frame = egui::Frame::none()
        .fill(pal.card_bg)
        .stroke(Stroke::new(1.0, pal.card_border))
        .rounding(Rounding::same(14.0))
        .inner_margin(Margin::same(margin_px))
        .shadow(egui::epaint::Shadow {
            offset: Vec2::new(0.0, 10.0),
            blur: 28.0,
            spread: 0.0,
            color: Color32::from_black_alpha(if pal.is_dark { 130 } else { 52 }),
        });

    let win_resp = egui::Window::new(title)
        .id(egui::Id::new(id_salt))
        .order(egui::Order::Foreground)
        .title_bar(false)
        .collapsible(false)
        .resizable(false)
        .movable(false)
        .fade_in(false)
        .fade_out(false)
        .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
        .constrain_to(screen.shrink(16.0))
        .default_size(Vec2::new(inner_w, max_inner_h))
        .min_width(inner_w)
        .max_width(inner_w)
        .max_height(max_inner_h)
        .frame(modal_frame)
        .show(ctx, |ui| {
            ui.set_min_width(inner_w);
            ui.set_max_width(inner_w);
            ui.set_max_height(max_inner_h);

            // Clean custom modal header row + Close (X) button
            input_row_with_right_widget(
                ui,
                |ui| {
                    if icon_button(ui, pal, Icon::Close, "Close (Esc)").clicked() {
                        *close_requested = true;
                    }
                },
                |ui, rem_w| {
                    ui.set_max_width(rem_w);
                    ui.add(
                        egui::Label::new(
                            RichText::new(title)
                                .font(semibold_font(ctx, 18.5))
                                .color(pal.ink),
                        )
                        .truncate(),
                    );
                },
            );

            ui.add_space(6.0);
            let sep_y = ui.cursor().top();
            let sep_l = ui.max_rect().left();
            let sep_r = ui.max_rect().right();
            ui.painter().line_segment(
                [Pos2::new(sep_l, sep_y), Pos2::new(sep_r, sep_y)],
                Stroke::new(1.0, pal.card_border),
            );
            ui.add_space(12.0);

            let scroll_out = egui::ScrollArea::vertical()
                .id_salt((id_salt, "modal_body_scroll"))
                .max_height(max_scroll_h)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.set_min_width(inner_w);
                    ui.set_max_width(inner_w);
                    add_contents(ui)
                });
            scroll_out.inner
        })?;

    let outer_rect = win_resp.response.rect;
    win_resp.inner.map(|val| (val, outer_rect))
}

/// Primary `#007D78` / `#0D9488` teal action button with optional leading vector [`Icon`].
pub fn primary_button(
    ui: &mut egui::Ui,
    pal: &Palette,
    icon: Option<Icon>,
    label: &str,
) -> Response {
    styled_action_button(
        ui,
        icon,
        label,
        pal.primary_btn,
        pal.primary_btn_hover,
        None,
        pal.primary_btn_text,
        13.5,
        Vec2::new(15.0, 9.0),
    )
}

/// Secondary `#FFFFFF` / `#1E2D3A` bordered action button with optional leading vector [`Icon`].
pub fn secondary_button(
    ui: &mut egui::Ui,
    pal: &Palette,
    icon: Option<Icon>,
    label: &str,
) -> Response {
    styled_action_button(
        ui,
        icon,
        label,
        pal.secondary_btn,
        pal.secondary_btn_hover,
        Some(pal.secondary_btn_border),
        pal.ink,
        13.2,
        Vec2::new(13.0, 8.5),
    )
}

/// Small secondary action button for compact toolbars, copy actions, and preset pills.
pub fn small_button(
    ui: &mut egui::Ui,
    pal: &Palette,
    icon: Option<Icon>,
    label: &str,
    selected: bool,
) -> Response {
    let (bg, hover_bg, border, fg) = if selected {
        (
            pal.primary_btn,
            pal.primary_btn_hover,
            pal.primary_btn,
            pal.primary_btn_text,
        )
    } else {
        (
            pal.secondary_btn,
            pal.secondary_btn_hover,
            pal.secondary_btn_border,
            pal.ink,
        )
    };
    styled_action_button(
        ui,
        icon,
        label,
        bg,
        hover_bg,
        Some(border),
        fg,
        12.2,
        Vec2::new(10.0, 5.5),
    )
}

/// Destructive / lock soft-danger button with optional leading vector [`Icon`].
pub fn danger_button(
    ui: &mut egui::Ui,
    pal: &Palette,
    icon: Option<Icon>,
    label: &str,
) -> Response {
    styled_action_button(
        ui,
        icon,
        label,
        pal.danger_bg,
        pal.danger_hover,
        Some(pal.danger_border),
        pal.danger_fg,
        13.2,
        Vec2::new(13.0, 8.5),
    )
}

/// Compact square icon-only button with tooltip (used for password Eye/EyeOff, theme Sun/Moon, modal Close).
pub fn icon_button(ui: &mut egui::Ui, pal: &Palette, icon: Icon, tooltip: &str) -> Response {
    let size = Vec2::splat(32.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let resp = if tooltip.is_empty() {
        resp
    } else {
        resp.on_hover_text(tooltip)
    };
    if resp.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
    if ui.is_rect_visible(rect) {
        let enabled = ui.is_enabled();
        let hover_t = ui
            .ctx()
            .animate_bool_with_time(resp.id, resp.hovered() && enabled, 0.12);
        let pressed = resp.is_pointer_button_down_on() && enabled;
        let bg = darken_pressed(
            lerp_color(pal.secondary_btn, pal.secondary_btn_hover, hover_t),
            pressed,
        );
        ui.painter().rect_filled(rect, Rounding::same(8.0), bg);
        ui.painter().rect_stroke(
            rect,
            Rounding::same(8.0),
            Stroke::new(1.0, pal.secondary_btn_border),
        );
        paint_icon(ui.painter(), rect.shrink(7.5), icon, pal.ink);
    }
    resp
}

#[allow(clippy::too_many_arguments)]
fn styled_action_button(
    ui: &mut egui::Ui,
    icon: Option<Icon>,
    label: &str,
    bg: Color32,
    hover_bg: Color32,
    border: Option<Color32>,
    fg: Color32,
    font_size: f32,
    pad: Vec2,
) -> Response {
    let font = semibold_font(ui.ctx(), font_size);
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), font, fg);
    let icon_side = (font_size + 2.5).round();
    let icon_extra = if icon.is_some() { icon_side + 7.0 } else { 0.0 };
    let desired = Vec2::new(
        pad.x * 2.0 + icon_extra + galley.size().x,
        (pad.y * 2.0 + galley.size().y.max(icon_side)).max(28.0),
    );

    let (rect, resp) = ui.allocate_exact_size(desired, Sense::click());
    if resp.hovered() && ui.is_enabled() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }

    if ui.is_rect_visible(rect) {
        let enabled = ui.is_enabled();
        let hover_t = ui
            .ctx()
            .animate_bool_with_time(resp.id, resp.hovered() && enabled, 0.12);
        let pressed = resp.is_pointer_button_down_on() && enabled;
        let fill = if !enabled {
            bg.gamma_multiply(0.50)
        } else {
            darken_pressed(lerp_color(bg, hover_bg, hover_t), pressed)
        };
        let draw_fg = if enabled { fg } else { fg.gamma_multiply(0.55) };

        ui.painter().rect_filled(rect, Rounding::same(8.0), fill);
        if let Some(b_col) = border {
            ui.painter()
                .rect_stroke(rect, Rounding::same(8.0), Stroke::new(1.0, b_col));
        }

        let mut cur_x = rect.left() + pad.x;
        if let Some(ic) = icon {
            let ic_rect = Rect::from_center_size(
                Pos2::new(cur_x + icon_side * 0.5, rect.center().y),
                Vec2::splat(icon_side),
            );
            paint_icon(ui.painter(), ic_rect, ic, draw_fg);
            cur_x += icon_side + 7.0;
        }

        let text_pos = Pos2::new(cur_x, rect.center().y - galley.size().y * 0.5);
        ui.painter().galley(text_pos, galley, draw_fg);
    }

    resp
}

/// Renders one `248px`-sidebar navigation row with `#244550`/`#16303D` active state and `#2DD4BF` left accent pill.
pub fn sidebar_nav_item(
    ui: &mut egui::Ui,
    pal: &Palette,
    icon: Icon,
    label: &str,
    badge: Option<&str>,
    active: bool,
) -> Response {
    let width = ui.available_width().max(180.0);
    let desired = Vec2::new(width, 40.0);
    let (rect, resp) = ui.allocate_exact_size(desired, Sense::click());
    if resp.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }

    if ui.is_rect_visible(rect) {
        let hover_t = ui
            .ctx()
            .animate_bool_with_time(resp.id, resp.hovered(), 0.12);
        let pressed = resp.is_pointer_button_down_on();

        if active {
            let bg = darken_pressed(pal.sidebar_active_bg, pressed);
            ui.painter().rect_filled(rect, Rounding::same(8.0), bg);
            let pill = Rect::from_min_max(
                Pos2::new(rect.left() + 3.0, rect.top() + 8.0),
                Pos2::new(rect.left() + 6.5, rect.bottom() - 8.0),
            );
            ui.painter()
                .rect_filled(pill, Rounding::same(2.0), pal.sidebar_accent);
        } else if hover_t > 0.001 || pressed {
            let bg = if pressed {
                darken_pressed(pal.sidebar_hover_bg, true)
            } else {
                lerp_color(Color32::TRANSPARENT, pal.sidebar_hover_bg, hover_t)
            };
            ui.painter().rect_filled(rect, Rounding::same(8.0), bg);
        }

        let fg = if active {
            pal.sidebar_text
        } else {
            lerp_color(pal.sidebar_inactive_text, pal.sidebar_text, hover_t)
        };
        let ic_color = if active { pal.sidebar_accent } else { fg };

        let ic_rect = Rect::from_center_size(
            Pos2::new(rect.left() + 22.0, rect.center().y),
            Vec2::splat(17.5),
        );
        paint_icon(ui.painter(), ic_rect, icon, ic_color);

        let font = if active {
            semibold_font(ui.ctx(), 14.0)
        } else {
            FontId::proportional(14.0)
        };
        let galley = ui
            .painter()
            .layout_no_wrap(label.to_owned(), font, fg);
        ui.painter().galley(
            Pos2::new(rect.left() + 40.0, rect.center().y - galley.size().y * 0.5),
            galley,
            fg,
        );

        if let Some(badge_txt) = badge.filter(|s| !s.is_empty()) {
            let b_font = semibold_font(ui.ctx(), 11.0);
            let b_galley = ui.painter().layout_no_wrap(
                badge_txt.to_owned(),
                b_font,
                pal.sidebar_text,
            );
            let b_w = (b_galley.size().x + 12.0).max(22.0);
            let b_rect = Rect::from_center_size(
                Pos2::new(rect.right() - 10.0 - b_w * 0.5, rect.center().y),
                Vec2::new(b_w, 19.0),
            );
            ui.painter().rect_filled(
                b_rect,
                Rounding::same(9.5),
                Color32::from_rgba_unmultiplied(45, 212, 191, 42),
            );
            ui.painter().galley(
                Pos2::new(
                    b_rect.center().x - b_galley.size().x * 0.5,
                    b_rect.center().y - b_galley.size().y * 0.5,
                ),
                b_galley,
                pal.sidebar_accent,
            );
        }
    }

    resp
}

/// Sidebar full-width subtle action button (e.g. `+ Connect a cloud`).
pub fn sidebar_action_button(
    ui: &mut egui::Ui,
    pal: &Palette,
    icon: Icon,
    label: &str,
) -> Response {
    let width = ui.available_width().max(160.0);
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, 36.0), Sense::click());
    if resp.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
    if ui.is_rect_visible(rect) {
        let hover_t = ui
            .ctx()
            .animate_bool_with_time(resp.id, resp.hovered(), 0.12);
        let pressed = resp.is_pointer_button_down_on();
        let hover_bg = pal.sidebar_active_bg.gamma_multiply(1.15);
        let bg = darken_pressed(lerp_color(pal.sidebar_active_bg, hover_bg, hover_t), pressed);
        ui.painter().rect_filled(rect, Rounding::same(8.0), bg);
        ui.painter().rect_stroke(
            rect,
            Rounding::same(8.0),
            Stroke::new(1.0, pal.sidebar_border),
        );

        let font = semibold_font(ui.ctx(), 13.0);
        let galley = ui
            .painter()
            .layout_no_wrap(label.to_owned(), font, pal.sidebar_text);
        let total_w = 16.0 + 7.0 + galley.size().x;
        let start_x = rect.center().x - total_w * 0.5;
        let ic_rect = Rect::from_center_size(
            Pos2::new(start_x + 8.0, rect.center().y),
            Vec2::splat(16.0),
        );
        paint_icon(ui.painter(), ic_rect, icon, pal.sidebar_accent);
        ui.painter().galley(
            Pos2::new(start_x + 23.0, rect.center().y - galley.size().y * 0.5),
            galley,
            pal.sidebar_text,
        );
    }
    resp
}

/// Rounded status pill with optional leading vector [`Icon`].
pub fn status_pill(
    ui: &mut egui::Ui,
    pal: &Palette,
    icon: Option<Icon>,
    label: &str,
    tone: PillTone,
) {
    let (bg, fg) = match tone {
        PillTone::Ok => (pal.ok_bg, pal.ok_fg),
        PillTone::Accent => (pal.accent_soft_bg, pal.accent_soft_fg),
        PillTone::Warn => (pal.warn_bg, pal.warn_fg),
        PillTone::Danger => (pal.danger_bg, pal.danger_fg),
        PillTone::Neutral => (pal.card_sub_bg, pal.muted),
    };

    let font = semibold_font(ui.ctx(), 11.8);
    let galley = ui.painter().layout_no_wrap(label.to_owned(), font, fg);
    let ic_w = if icon.is_some() { 13.5 + 5.0 } else { 0.0 };
    let desired = Vec2::new(18.0 + ic_w + galley.size().x, 24.0);
    let (rect, _) = ui.allocate_exact_size(desired, Sense::hover());

    if ui.is_rect_visible(rect) {
        ui.painter().rect_filled(rect, Rounding::same(12.0), bg);
        ui.painter().rect_stroke(
            rect,
            Rounding::same(12.0),
            Stroke::new(1.0, fg.gamma_multiply(0.24)),
        );
        let mut x = rect.left() + 9.0;
        if let Some(ic) = icon {
            let ic_rect = Rect::from_center_size(
                Pos2::new(x + 6.75, rect.center().y),
                Vec2::splat(13.5),
            );
            paint_icon(ui.painter(), ic_rect, ic, fg);
            x += ic_w;
        }
        ui.painter().galley(
            Pos2::new(x, rect.center().y - galley.size().y * 0.5),
            galley,
            fg,
        );
    }
}

/// Clean slim progress bar matching CloudBridge's `TransferProgress` (`4-6px` rounded bar).
pub fn progress_bar_clean(ui: &mut egui::Ui, pal: &Palette, fraction: f32, height: f32) {
    let width = ui.available_width().max(40.0);
    let h = height.max(4.0);
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, h), Sense::hover());
    let clamped = fraction.clamp(0.0, 1.0);
    let animated = ui
        .ctx()
        .animate_value_with_time(resp.id, clamped, 0.18)
        .clamp(0.0, 1.0);
    if ui.is_rect_visible(rect) {
        let r = Rounding::same(h * 0.5);
        ui.painter().rect_filled(rect, r, pal.progress_track);
        if animated > 0.005 {
            let fill_w = (rect.width() * animated).max(h);
            let fill_rect =
                Rect::from_min_max(rect.min, Pos2::new(rect.left() + fill_w, rect.bottom()));
            ui.painter().rect_filled(fill_rect, r, pal.primary_btn);
        }
    }
}

/// Apple-style segmented control: calm `card_sub_bg` rounded track (`8px` radius, `2px` inset)
/// with a crisp elevated `card_bg` active pill (`6px` radius + subtle shadow) and smooth hover
/// tint on inactive segments. Returns `true` when `*current` changes.
pub fn segmented_control<T: Copy + PartialEq>(
    ui: &mut egui::Ui,
    pal: &Palette,
    current: &mut T,
    options: &[(T, &str)],
) -> bool {
    if options.is_empty() {
        return false;
    }

    let inset = 2.0;
    let pad_x = 12.0;
    let height = 30.0;
    let seg_h = height - inset * 2.0;

    let measure_font = semibold_font(ui.ctx(), 12.5);
    let seg_widths: Vec<f32> = options
        .iter()
        .map(|(_, label)| {
            let galley =
                ui.painter()
                    .layout_no_wrap((*label).to_owned(), measure_font.clone(), pal.ink);
            (galley.size().x + pad_x * 2.0).max(48.0)
        })
        .collect();
    let total_w = inset * 2.0 + seg_widths.iter().sum::<f32>();

    let (track_rect, track_resp) =
        ui.allocate_exact_size(Vec2::new(total_w, height), Sense::hover());

    let visible = ui.is_rect_visible(track_rect);
    if visible {
        ui.painter()
            .rect_filled(track_rect, Rounding::same(8.0), pal.card_sub_bg);
        ui.painter().rect_stroke(
            track_rect,
            Rounding::same(8.0),
            Stroke::new(1.0, pal.card_border),
        );
    }

    let mut changed = false;
    let mut cur_x = track_rect.left() + inset;
    let enabled = ui.is_enabled();

    for (idx, (&(val, label), &seg_w)) in options.iter().zip(seg_widths.iter()).enumerate() {
        let seg_rect = Rect::from_min_size(
            Pos2::new(cur_x, track_rect.top() + inset),
            Vec2::new(seg_w, seg_h),
        );
        cur_x += seg_w;

        let seg_id = track_resp.id.with(idx);
        let resp = ui.interact(seg_rect, seg_id, Sense::click());
        let is_active = *current == val;

        if resp.hovered() && enabled {
            ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
        }

        let hover_t = ui.ctx().animate_bool_with_time(
            resp.id,
            resp.hovered() && !is_active && enabled,
            0.12,
        );
        let pressed = resp.is_pointer_button_down_on() && enabled;

        if visible {
            if is_active {
                let pill_shadow = egui::epaint::Shadow {
                    offset: Vec2::new(0.0, 1.0),
                    blur: 4.0,
                    spread: 0.0,
                    color: Color32::from_black_alpha(if pal.is_dark { 48 } else { 18 }),
                };
                ui.painter()
                    .add(pill_shadow.as_shape(seg_rect, Rounding::same(6.0)));
                ui.painter().rect_filled(
                    seg_rect,
                    Rounding::same(6.0),
                    darken_pressed(pal.card_bg, pressed),
                );
                ui.painter().rect_stroke(
                    seg_rect,
                    Rounding::same(6.0),
                    Stroke::new(0.75, pal.card_border),
                );
            } else if hover_t > 0.001 || pressed {
                let tint = if pressed {
                    if pal.is_dark {
                        Color32::from_white_alpha(26)
                    } else {
                        Color32::from_black_alpha(20)
                    }
                } else {
                    let target = if pal.is_dark {
                        Color32::from_white_alpha(18)
                    } else {
                        Color32::from_black_alpha(12)
                    };
                    lerp_color(Color32::TRANSPARENT, target, hover_t)
                };
                ui.painter().rect_filled(seg_rect, Rounding::same(6.0), tint);
            }

            let fg = if is_active {
                pal.ink
            } else {
                lerp_color(pal.muted, pal.ink, hover_t)
            };
            let font = if is_active {
                semibold_font(ui.ctx(), 12.5)
            } else {
                FontId::proportional(12.5)
            };
            let galley = ui.painter().layout_no_wrap(label.to_owned(), font, fg);
            ui.painter().galley(
                Pos2::new(
                    seg_rect.center().x - galley.size().x * 0.5,
                    seg_rect.center().y - galley.size().y * 0.5,
                ),
                galley,
                fg,
            );
        }

        if resp.clicked() && enabled && !is_active {
            *current = val;
            changed = true;
        }
    }

    changed
}

/// Visual horizontal 4-step onboarding stepper (`1. Welcome` -> `2. Connect a Cloud` -> ...).
pub fn step_indicator(ui: &mut egui::Ui, pal: &Palette, steps: &[&str], active_idx: usize) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        for (idx, &title) in steps.iter().enumerate() {
            let done = idx < active_idx;
            let active = idx == active_idx;

            let circle_size = Vec2::splat(24.0);
            let (c_rect, _) = ui.allocate_exact_size(circle_size, Sense::hover());
            if ui.is_rect_visible(c_rect) {
                if done || active {
                    ui.painter()
                        .circle_filled(c_rect.center(), 11.5, pal.primary_btn);
                } else {
                    ui.painter().circle_filled(c_rect.center(), 11.5, pal.card_sub_bg);
                    ui.painter().circle_stroke(
                        c_rect.center(),
                        11.5,
                        Stroke::new(1.2, pal.card_border),
                    );
                }

                if done {
                    paint_icon(
                        ui.painter(),
                        c_rect.shrink(5.5),
                        Icon::Check,
                        pal.primary_btn_text,
                    );
                } else {
                    let num_fg = if active {
                        pal.primary_btn_text
                    } else {
                        pal.muted
                    };
                    ui.painter().text(
                        c_rect.center(),
                        Align2::CENTER_CENTER,
                        format!("{}", idx + 1),
                        semibold_font(ui.ctx(), 12.0),
                        num_fg,
                    );
                }
            }

            let label_fg = if active || done { pal.ink } else { pal.muted };
            let label_font = if active {
                semibold_font(ui.ctx(), 13.5)
            } else {
                FontId::proportional(13.2)
            };
            ui.label(RichText::new(title).font(label_font).color(label_fg));

            if idx + 1 < steps.len() {
                let (line_rect, _) = ui.allocate_exact_size(Vec2::new(26.0, 24.0), Sense::hover());
                let line_col = if done {
                    pal.primary_btn
                } else {
                    pal.card_border
                };
                ui.painter().line_segment(
                    [
                        Pos2::new(line_rect.left() + 2.0, line_rect.center().y),
                        Pos2::new(line_rect.right() - 2.0, line_rect.center().y),
                    ],
                    Stroke::new(1.5, line_col),
                );
            }
        }
    });
}

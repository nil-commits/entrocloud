//! Realistic populated consumer demo state & 8-step automated `--screenshot-tour <OUTPUT_DIR>`
//! capture state machine (`egui::ViewportCommand::Screenshot` + `egui::Event::Screenshot` + `png::Encoder`).

use std::io::BufWriter;
use std::path::{Path, PathBuf};

use chrono::{Duration as ChronoDuration, Utc};
use eframe::egui;
use entrocloud_types::{
    BackendHealth, BackendKind, BackendQuota, BackupJobSummary, BackupRunReport, CapabilityUri,
    CryptoBenchmarkReport, DetectedCloudFolder, DriveStats, EntryKind, HardwareCryptoCaps,
    HydrationState, KeyboxSummary, RemoteAccountSummary, RemoteTestReport, RoutingPolicy,
    ThroughputSnapshot, VaultEntrySummary, VaultStatusReport,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::theme::{ThemePreference, UiPrefs};
use crate::views::NavPage;
use crate::wizard::{WizardProvider, WizardState, WizardStep};
use crate::worker::SharedWorkerState;

/// Exact 8 screenshot filenames captured during `--screenshot-tour <OUTPUT_DIR>`.
pub const TOUR_STEPS: [(usize, &str, ThemePreference); 8] = [
    (0, "01_welcome_light.png", ThemePreference::Light),
    (1, "02_gdrive_api_guide_light.png", ThemePreference::Light),
    (2, "03_backups_overview_light.png", ThemePreference::Light),
    (3, "04_backups_overview_dark.png", ThemePreference::Dark),
    (4, "05_vault_files_grid_light.png", ThemePreference::Light),
    (5, "06_cloud_connections_light.png", ThemePreference::Light),
    (6, "07_computer_drive_dark.png", ThemePreference::Dark),
    (
        7,
        "08_sharing_and_settings_light.png",
        ThemePreference::Light,
    ),
];

/// State machine driving `--screenshot-tour <OUTPUT_DIR>`.
pub struct ScreenshotTourDriver {
    pub output_dir: PathBuf,
    pub step_idx: usize,
    pub settle_frames: u32,
    pub screenshot_requested: bool,
    pub wait_frames: u32,
    pub written_files: Vec<PathBuf>,
    pub error: Option<String>,
}

impl ScreenshotTourDriver {
    #[must_use]
    pub fn new(output_dir: PathBuf) -> Self {
        Self {
            output_dir,
            step_idx: 0,
            settle_frames: 0,
            screenshot_requested: false,
            wait_frames: 0,
            written_files: Vec::with_capacity(TOUR_STEPS.len()),
            error: None,
        }
    }

    /// Returns `true` when step 7 (`08_sharing_and_settings_light.png`) is active so Sharing & Settings
    /// render side-by-side in 2 columns.
    #[must_use]
    pub fn is_split_sharing_and_settings(&self) -> bool {
        self.step_idx == 7
    }
}

/// Populates `SharedWorkerState` with realistic, calm consumer demo data (zero live daemon needed).
pub fn populate_demo_worker_state(state: &mut SharedWorkerState) {
    let now = Utc::now();
    let vault_id = Uuid::from_u128(0x0195_A4C0_77E1_7B20_91C4_2280_EC10_0001);

    let gdrive_quota = BackendQuota {
        backend_id: "GoogleDrive".to_owned(),
        total_bytes: 100 * 1024 * 1024 * 1024,
        used_bytes: 28 * 1024 * 1024 * 1024,
        available_bytes: 72 * 1024 * 1024 * 1024,
    };
    let onedrive_quota = BackendQuota {
        backend_id: "OneDrive".to_owned(),
        total_bytes: 1000 * 1024 * 1024 * 1024,
        used_bytes: 142 * 1024 * 1024 * 1024,
        available_bytes: 858 * 1024 * 1024 * 1024,
    };
    let r2_quota = BackendQuota {
        backend_id: "CloudflareR2".to_owned(),
        total_bytes: 500 * 1024 * 1024 * 1024,
        used_bytes: 64 * 1024 * 1024 * 1024,
        available_bytes: 436 * 1024 * 1024 * 1024,
    };

    let remotes = vec![
        RemoteAccountSummary {
            id: "GoogleDrive".to_owned(),
            kind: "gdrive".to_owned(),
            root: "/EntroCloud".to_owned(),
            health: BackendHealth {
                backend_id: "GoogleDrive".to_owned(),
                kind: BackendKind::GoogleDrive,
                healthy: true,
                latency_ms: Some(34),
                last_error: None,
                quota: gdrive_quota.clone(),
            },
        },
        RemoteAccountSummary {
            id: "OneDrive".to_owned(),
            kind: "onedrive".to_owned(),
            root: "/EntroCloud".to_owned(),
            health: BackendHealth {
                backend_id: "OneDrive".to_owned(),
                kind: BackendKind::OneDrive,
                healthy: true,
                latency_ms: Some(41),
                last_error: None,
                quota: onedrive_quota.clone(),
            },
        },
        RemoteAccountSummary {
            id: "CloudflareR2".to_owned(),
            kind: "s3".to_owned(),
            root: "/EntroCloud".to_owned(),
            health: BackendHealth {
                backend_id: "CloudflareR2".to_owned(),
                kind: BackendKind::S3,
                healthy: true,
                latency_ms: Some(28),
                last_error: None,
                quota: r2_quota.clone(),
            },
        },
    ];

    let backup_jobs = vec![
        BackupJobSummary {
            id: "job-docs".to_owned(),
            name: "Documents".to_owned(),
            source_path: r"C:\Users\Alex\Documents".to_owned(),
            vault_folder: "/Backups/Documents".to_owned(),
            interval_minutes: 15,
            enabled: true,
            excludes: vec![
                "desktop.ini".to_owned(),
                "Thumbs.db".to_owned(),
                "~$*".to_owned(),
            ],
            status: "Backed up".to_owned(),
            last_attempt_at: Some(now - ChronoDuration::minutes(6)),
            last_success_at: Some(now - ChronoDuration::minutes(6)),
            last_error: None,
            last_files_synced: 348,
            last_bytes_synced: 1_840 * 1024 * 1024,
        },
        BackupJobSummary {
            id: "job-photos".to_owned(),
            name: "Family Photos".to_owned(),
            source_path: r"C:\Users\Alex\Pictures\Family".to_owned(),
            vault_folder: "/Backups/Family Photos".to_owned(),
            interval_minutes: 60,
            enabled: true,
            excludes: vec!["Thumbs.db".to_owned()],
            status: "Backed up".to_owned(),
            last_attempt_at: Some(now - ChronoDuration::minutes(24)),
            last_success_at: Some(now - ChronoDuration::minutes(24)),
            last_error: None,
            last_files_synced: 2_410,
            last_bytes_synced: 18_600 * 1024 * 1024,
        },
        BackupJobSummary {
            id: "job-taxes".to_owned(),
            name: "Tax & Finance 2026".to_owned(),
            source_path: r"C:\Users\Alex\Documents\Taxes 2026".to_owned(),
            vault_folder: "/Backups/Taxes 2026".to_owned(),
            interval_minutes: 360,
            enabled: true,
            excludes: vec!["~$*".to_owned()],
            status: "Backed up".to_owned(),
            last_attempt_at: Some(now - ChronoDuration::hours(2)),
            last_success_at: Some(now - ChronoDuration::hours(2)),
            last_error: None,
            last_files_synced: 64,
            last_bytes_synced: 215 * 1024 * 1024,
        },
    ];

    let report = VaultStatusReport {
        vault_id: Some(vault_id),
        unlocked: true,
        mounted: true,
        mount_point: Some(r"C:\Users\Alex\EntroCloud".to_owned()),
        manifest_revision: 42,
        keybox_epoch: 2,
        routing_policy: Some(RoutingPolicy::QuotaPooled {
            pool_backends: vec![
                "GoogleDrive".to_owned(),
                "OneDrive".to_owned(),
                "CloudflareR2".to_owned(),
            ],
        }),
        remotes,
        pooled_quota: Some(BackendQuota {
            backend_id: "pool".to_owned(),
            total_bytes: 1600 * 1024 * 1024 * 1024,
            used_bytes: 234 * 1024 * 1024 * 1024,
            available_bytes: 1366 * 1024 * 1024 * 1024,
        }),
        throughput: ThroughputSnapshot {
            upload_bytes_per_sec: 38 * 1024 * 1024,
            download_bytes_per_sec: 92 * 1024 * 1024,
            pending_dirty_ops: 0,
            cache_bytes_used: 128 * 1024 * 1024,
            sampled_at: Some(now),
        },
        drive_stats: DriveStats {
            bytes_read: 1_524_000_000,
            bytes_written: 648_500_000,
            chunks_hydrated: 96,
            cache_hits: 1420,
            open_handles: 2,
        },
        conflict_count: 0,
        backups_paused: false,
        backup_jobs,
        active_activity: None,
    };

    state.daemon_connected = true;
    state.apply_status(report);

    // Smooth realistic sparkline curve
    state.up_mib_history.clear();
    state.down_mib_history.clear();
    for i in 0..48 {
        let t = (i as f32) * 0.22;
        let up = 18.0 + (t.sin().abs() * 28.0) + ((t * 0.5).cos().abs() * 12.0);
        let down = 34.0 + ((t + 0.8).sin().abs() * 56.0);
        state.up_mib_history.push_back(up);
        state.down_mib_history.push_back(down);
    }
    state.peak_up_mib_s = 64.2;
    state.peak_down_mib_s = 118.5;

    state.current_dir = "/Documents".to_owned();
    state.entries = vec![
        VaultEntrySummary {
            inode: 10,
            name: "Contracts".to_owned(),
            virtual_path: "/Documents/Contracts".to_owned(),
            kind: EntryKind::Directory,
            size: 0,
            hydration: HydrationState::OnlineOnly,
            pinned: false,
            version: 3,
            modified_at: now - ChronoDuration::days(2),
        },
        VaultEntrySummary {
            inode: 11,
            name: "Receipts 2026".to_owned(),
            virtual_path: "/Documents/Receipts 2026".to_owned(),
            kind: EntryKind::Directory,
            size: 0,
            hydration: HydrationState::OnlineOnly,
            pinned: false,
            version: 5,
            modified_at: now - ChronoDuration::hours(14),
        },
        VaultEntrySummary {
            inode: 12,
            name: "Passport Scan.pdf".to_owned(),
            virtual_path: "/Documents/Passport Scan.pdf".to_owned(),
            kind: EntryKind::File,
            size: 4_420_000,
            hydration: HydrationState::Pinned,
            pinned: true,
            version: 1,
            modified_at: now - ChronoDuration::days(18),
        },
        VaultEntrySummary {
            inode: 13,
            name: "Household Budget.xlsx".to_owned(),
            virtual_path: "/Documents/Household Budget.xlsx".to_owned(),
            kind: EntryKind::File,
            size: 862_000,
            hydration: HydrationState::LocallyCached,
            pinned: false,
            version: 9,
            modified_at: now - ChronoDuration::hours(3),
        },
        VaultEntrySummary {
            inode: 14,
            name: "Recovery Codes.md".to_owned(),
            virtual_path: "/Documents/Recovery Codes.md".to_owned(),
            kind: EntryKind::File,
            size: 3_480,
            hydration: HydrationState::Pinned,
            pinned: true,
            version: 2,
            modified_at: now - ChronoDuration::days(7),
        },
        VaultEntrySummary {
            inode: 15,
            name: "Property Deed.pdf".to_owned(),
            virtual_path: "/Documents/Property Deed.pdf".to_owned(),
            kind: EntryKind::File,
            size: 12_900_000,
            hydration: HydrationState::OnlineOnly,
            pinned: false,
            version: 1,
            modified_at: now - ChronoDuration::days(45),
        },
        VaultEntrySummary {
            inode: 16,
            name: "Insurance Policy.pdf".to_owned(),
            virtual_path: "/Documents/Insurance Policy.pdf".to_owned(),
            kind: EntryKind::File,
            size: 6_150_000,
            hydration: HydrationState::LocallyCached,
            pinned: false,
            version: 2,
            modified_at: now - ChronoDuration::days(11),
        },
        VaultEntrySummary {
            inode: 17,
            name: "Project Notes.txt".to_owned(),
            virtual_path: "/Documents/Project Notes.txt".to_owned(),
            kind: EntryKind::File,
            size: 14_200,
            hydration: HydrationState::LocallyCached,
            pinned: false,
            version: 4,
            modified_at: now - ChronoDuration::hours(1),
        },
    ];

    state.detected_clouds = vec![
        DetectedCloudFolder {
            provider: "OneDrive".to_owned(),
            suggested_id: "OneDrive-PC".to_owned(),
            path: r"C:\Users\Alex\OneDrive".to_owned(),
        },
        DetectedCloudFolder {
            provider: "Google Drive".to_owned(),
            suggested_id: "GoogleDrive-PC".to_owned(),
            path: r"G:\My Drive".to_owned(),
        },
    ];

    state.remote_tests.insert(
        "GoogleDrive".to_owned(),
        RemoteTestReport {
            id: "GoogleDrive".to_owned(),
            kind: "gdrive".to_owned(),
            healthy: true,
            latency_ms: 34,
            quota: gdrive_quota,
            message: "Verified read/write access in 34 ms".to_owned(),
        },
    );
    state.remote_tests.insert(
        "OneDrive".to_owned(),
        RemoteTestReport {
            id: "OneDrive".to_owned(),
            kind: "onedrive".to_owned(),
            healthy: true,
            latency_ms: 41,
            quota: onedrive_quota,
            message: "Verified read/write access in 41 ms".to_owned(),
        },
    );
    state.remote_tests.insert(
        "CloudflareR2".to_owned(),
        RemoteTestReport {
            id: "CloudflareR2".to_owned(),
            kind: "s3".to_owned(),
            healthy: true,
            latency_ms: 28,
            quota: r2_quota,
            message: "Verified bucket access in 28 ms".to_owned(),
        },
    );

    state.last_backup_report = Some(BackupRunReport {
        job_id: "*".to_owned(),
        preview: false,
        files_scanned: 2_822,
        files_uploaded: 6,
        files_unchanged: 2_816,
        bytes_uploaded: 24 * 1024 * 1024,
        elapsed_ms: 840,
        message: "Protected 3 PC folders across 3 connected clouds • Last verified 6 minutes ago."
            .to_owned(),
    });

    let sample_uri = CapabilityUri {
        backend_hint: "GoogleDrive".to_owned(),
        root_locator: "/EntroCloud".to_owned(),
        share_id: Uuid::from_u128(0x0195_A4C0_9911_7D40_88B2_1144_EC20_0099),
        share_root_key: Zeroizing::new([0x3Au8; 32]),
        owner_ed25519_pubkey: [0x7Cu8; 32],
    };
    if let Ok(encoded) = sample_uri.encode() {
        state.latest_share_uri = Some((sample_uri.share_id.to_string(), Zeroizing::new(encoded)));
    }

    state.keybox_info = Some(KeyboxSummary {
        vault_id,
        epoch: 2,
        owner_pubkey_hex: "7c94e10288a45b19d042e8193a77bc107c94e10288a45b19d042e8193a77bc10"
            .to_owned(),
        recipient_ids: vec![
            "9f41c820be7104a2d83910fe44129b7c".to_owned(),
            "3a88d19e5021bc49f01277ac88310de4".to_owned(),
        ],
    });

    state.crypto_bench = Some(CryptoBenchmarkReport {
        caps: HardwareCryptoCaps {
            arch: "x86_64".to_owned(),
            aes_hw: true,
            pclmul_hw: true,
            vaes_hw: true,
            avx2_hw: true,
            mandatory_satisfied: true,
            backend_name: "Hardware AES-256-GCM (VAES + AVX2)".to_owned(),
        },
        total_mib: 128,
        encrypt_mib_per_sec: 4_966.4,
        decrypt_mib_per_sec: 5_242.8,
        encrypt_elapsed_ms: 25,
        decrypt_elapsed_ms: 24,
    });
}

/// Applies the UI state for step `idx` (`0..8`) of `--screenshot-tour`.
pub fn configure_tour_step_ui(
    idx: usize,
    worker_state: &mut SharedWorkerState,
    prefs_out: &mut UiPrefs,
    active_page_out: &mut NavPage,
    wizard: &mut WizardState,
) {
    let Some(&(_, _, theme)) = TOUR_STEPS.get(idx) else {
        return;
    };
    prefs_out.theme = theme;
    prefs_out.start_with_os = true;

    populate_demo_worker_state(worker_state);

    match idx {
        0 => {
            // 01_welcome_light.png — true first-run state
            if let Some(ref mut st) = worker_state.status {
                st.remotes.clear();
                st.unlocked = false;
            }
            prefs_out.wizard_completed = false;
            wizard.open_full(WizardStep::Welcome);
        }
        1 => {
            // 02_gdrive_api_guide_light.png — clean first-run Google Drive guide + form above the fold
            if let Some(ref mut st) = worker_state.status {
                st.remotes.clear();
                st.unlocked = false;
            }
            prefs_out.wizard_completed = false;
            wizard.open_full(WizardStep::ConnectCloud);
            wizard.select_provider(WizardProvider::GoogleDrive);
            wizard.oauth_client_id =
                "482910374612-k9m2v8x4q1p7entrocloud.apps.googleusercontent.com".to_owned();
        }
        2 => {
            // 03_backups_overview_light.png
            prefs_out.wizard_completed = true;
            wizard.open = false;
            *active_page_out = NavPage::Backups;
        }
        3 => {
            // 04_backups_overview_dark.png
            prefs_out.wizard_completed = true;
            wizard.open = false;
            *active_page_out = NavPage::Backups;
        }
        4 => {
            // 05_vault_files_grid_light.png
            prefs_out.wizard_completed = true;
            wizard.open = false;
            prefs_out.file_view_grid = true;
            *active_page_out = NavPage::MyFiles;
        }
        5 => {
            // 06_cloud_connections_light.png
            prefs_out.wizard_completed = true;
            wizard.open = false;
            *active_page_out = NavPage::CloudConnections;
        }
        6 => {
            // 07_computer_drive_dark.png
            prefs_out.wizard_completed = true;
            wizard.open = false;
            *active_page_out = NavPage::ComputerDrive;
        }
        7 => {
            // 08_sharing_and_settings_light.png
            prefs_out.wizard_completed = true;
            wizard.open = false;
            *active_page_out = NavPage::Sharing;
        }
        _ => {}
    }
}

/// Encodes an `egui::ColorImage` screenshot directly into an 8-bit RGBA `.png` file.
pub fn write_color_image_png(image: &egui::ColorImage, dest: &Path) -> Result<(), String> {
    let width = u32::try_from(image.size[0]).map_err(|_| "Invalid screenshot width".to_owned())?;
    let height =
        u32::try_from(image.size[1]).map_err(|_| "Invalid screenshot height".to_owned())?;
    if width == 0 || height == 0 {
        return Err("Empty screenshot image".to_owned());
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed creating screenshot directory {}: {e}", parent.display()))?;
    }

    let mut rgba = Vec::with_capacity(image.pixels.len().saturating_mul(4));
    for px in &image.pixels {
        rgba.extend_from_slice(&px.to_srgba_unmultiplied());
    }

    let file = std::fs::File::create(dest)
        .map_err(|e| format!("Failed creating screenshot {}: {e}", dest.display()))?;
    let buf_writer = BufWriter::new(file);
    let mut encoder = png::Encoder::new(buf_writer, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder
        .write_header()
        .map_err(|e| format!("Failed writing PNG header {}: {e}", dest.display()))?;
    writer
        .write_image_data(&rgba)
        .map_err(|e| format!("Failed writing PNG pixels {}: {e}", dest.display()))?;
    writer
        .finish()
        .map_err(|e| format!("Failed finalizing PNG {}: {e}", dest.display()))?;

    Ok(())
}

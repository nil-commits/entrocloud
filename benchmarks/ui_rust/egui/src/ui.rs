use eframe::egui::{
    self, Color32, FontId, Margin, Pos2, ProgressBar, RichText, Rounding, Slider, Stroke, Vec2,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::ipc::{ConnectedIpcClient, TelemetryFrame};
use crate::win32_metrics::{
    qpc_elapsed_ms, qpc_now, round3, sample_current_process_memory, DistributionStats,
    ProcessMemorySnapshot,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Unified,
    VaultStatus,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutingPolicy {
    Targeted,
    MirroredRaid1,
    QuotaPooled,
}

impl RoutingPolicy {
    pub fn label(self) -> &'static str {
        match self {
            Self::Targeted => "Targeted",
            Self::MirroredRaid1 => "Mirrored RAID-1",
            Self::QuotaPooled => "Quota-Pooled",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Targeted => "Pin encrypted vault shards deterministically to primary low-latency bucket.",
            Self::MirroredRaid1 => "Write-through 2-of-3 synchronous ciphertext replication across providers.",
            Self::QuotaPooled => "Stripe Reed-Solomon erasure chunks proportionally across free cloud quota.",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BenchMode {
    Interactive,
    Cold {
        main_entry_qpc: i64,
        ipc_ready_qpc: i64,
        spawn_qpc: Option<i64>,
    },
    Fps60 {
        main_entry_qpc: i64,
        target_frames: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColdBenchResult {
    pub mode: String,
    pub backend: String,
    pub gpu_adapter: String,
    pub ipc_pipe: String,
    pub ipc_mode: String,
    pub initial_ipc_seq: u64,
    pub ipc_connect_first_frame_ms: f64,
    pub internal_cold_start_ms: f64,
    pub external_cold_start_ms: Option<f64>,
    pub frame1_update_cpu_ms: f64,
    pub memory: ProcessMemorySnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fps60BenchResult {
    pub mode: String,
    pub backend: String,
    pub gpu_adapter: String,
    pub ipc_pipe: String,
    pub ipc_mode: String,
    pub target_ipc_frames: u32,
    pub rendered_ipc_frames: u32,
    pub total_gpu_frames: u32,
    pub elapsed_wall_ms: f64,
    pub achieved_fps: f64,
    pub frame_pacing_ms: DistributionStats,
    pub frame_render_cpu_ms: DistributionStats,
    pub memory: ProcessMemorySnapshot,
}

#[derive(Debug, Default)]
pub struct BenchOutputSlot {
    pub cold: Option<ColdBenchResult>,
    pub fps60: Option<Fps60BenchResult>,
}

pub struct ZeroVaultApp {
    ipc: ConnectedIpcClient,
    backend_name: String,
    gpu_adapter: String,
    bench_mode: BenchMode,
    output_slot: Arc<Mutex<BenchOutputSlot>>,

    // UI interactive state
    active_tab: ActiveTab,
    vault_locked: bool,
    mount_path: String,
    routing_policy: RoutingPolicy,
    cache_limit_gib: f32,

    // Frame timing telemetry
    total_gpu_frames: u32,
    ipc_driven_frames: u32,
    last_rendered_seq: u64,
    stream_start_qpc: Option<i64>,
    prev_ipc_frame_qpc: Option<i64>,
    frame1_update_cpu_ms: f64,
    frame_pacing_samples_ms: Vec<f64>,
    frame_render_samples_ms: Vec<f64>,
    exit_captured: bool,
}

impl ZeroVaultApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        ipc: ConnectedIpcClient,
        backend_name: String,
        bench_mode: BenchMode,
        output_slot: Arc<Mutex<BenchOutputSlot>>,
    ) -> Self {
        configure_dark_theme(&cc.egui_ctx);

        let gpu_adapter = detect_gpu_adapter_string(cc);
        {
            let mut guard = ipc.state.lock();
            guard.egui_ctx = Some(cc.egui_ctx.clone());
        }

        Self {
            ipc,
            backend_name,
            gpu_adapter,
            bench_mode,
            output_slot,
            active_tab: ActiveTab::Unified,
            vault_locked: false,
            mount_path: r"Z:\ZeroVault".to_owned(),
            routing_policy: RoutingPolicy::QuotaPooled,
            cache_limit_gib: 32.0,
            total_gpu_frames: 0,
            ipc_driven_frames: 0,
            last_rendered_seq: 0,
            stream_start_qpc: None,
            prev_ipc_frame_qpc: None,
            frame1_update_cpu_ms: 0.0,
            frame_pacing_samples_ms: Vec::with_capacity(320),
            frame_render_samples_ms: Vec::with_capacity(320),
            exit_captured: false,
        }
    }

    fn render_header(&mut self, ui: &mut egui::Ui, snap: &TelemetrySnapshot) {
        let card_bg = Color32::from_rgb(18, 24, 38);
        let border = Color32::from_rgb(34, 46, 68);

        egui::Frame::none()
            .fill(card_bg)
            .stroke(Stroke::new(1.0, border))
            .rounding(Rounding::same(10.0))
            .inner_margin(Margin::symmetric(16.0, 12.0))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new("◆ ZEROVAULT")
                            .font(FontId::proportional(20.0))
                            .strong()
                            .color(Color32::from_rgb(240, 246, 255)),
                    );
                    ui.add_space(6.0);
                    badge_pill(
                        ui,
                        &format!("eframe 0.29.1 • {}", self.backend_name),
                        Color32::from_rgb(22, 38, 64),
                        Color32::from_rgb(96, 165, 250),
                    );

                    // Vault Lock/Unlock status badge
                    if self.vault_locked {
                        badge_pill(
                            ui,
                            "LOCKED",
                            Color32::from_rgb(69, 18, 26),
                            Color32::from_rgb(248, 113, 113),
                        );
                    } else {
                        badge_pill(
                            ui,
                            "● UNLOCKED",
                            Color32::from_rgb(12, 54, 42),
                            Color32::from_rgb(52, 211, 153),
                        );
                    }

                    // Active mount path badge
                    badge_pill(
                        ui,
                        &format!("Mount: {}", self.mount_path),
                        Color32::from_rgb(26, 34, 52),
                        Color32::from_rgb(203, 213, 225),
                    );

                    // Post-quantum + hardware AEAD encryption badge
                    badge_pill(
                        ui,
                        "AES-256-GCM VAES + ML-KEM-768",
                        Color32::from_rgb(56, 38, 12),
                        Color32::from_rgb(251, 191, 36),
                    );
                });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let ipc_color = if snap.connected {
                        Color32::from_rgb(45, 212, 191)
                    } else {
                        Color32::from_rgb(248, 113, 113)
                    };
                    ui.label(
                        RichText::new(format!(
                            "IPC Pipe: {}  •  Seq #{}  •  GPU: {}",
                            snap.pipe_name, snap.frame.seq, self.gpu_adapter
                        ))
                        .font(FontId::monospace(11.5))
                        .color(ipc_color),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.selectable_value(&mut self.active_tab, ActiveTab::Settings, "Settings");
                        ui.selectable_value(
                            &mut self.active_tab,
                            ActiveTab::VaultStatus,
                            "Vault Status",
                        );
                        ui.selectable_value(
                            &mut self.active_tab,
                            ActiveTab::Unified,
                            "Unified Dashboard",
                        );
                    });
                });
            });
    }

    fn render_transfer_meter_panel(&self, ui: &mut egui::Ui, snap: &TelemetrySnapshot) {
        let card_bg = Color32::from_rgb(18, 24, 38);
        let subcard_bg = Color32::from_rgb(13, 18, 29);
        let border = Color32::from_rgb(34, 46, 68);

        egui::Frame::none()
            .fill(card_bg)
            .stroke(Stroke::new(1.0, border))
            .rounding(Rounding::same(10.0))
            .inner_margin(Margin::symmetric(16.0, 14.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Live Transfer Telemetry & Multi-Cloud Pool")
                            .font(FontId::proportional(16.5))
                            .strong()
                            .color(Color32::from_rgb(236, 242, 252)),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        badge_pill(
                            ui,
                            &format!("Active Chunks: {}", snap.frame.active_chunks),
                            Color32::from_rgb(24, 42, 68),
                            Color32::from_rgb(56, 189, 248),
                        );
                        ui.add_space(6.0);
                        badge_pill(
                            ui,
                            &format!("Policy: {}", self.routing_policy.label()),
                            Color32::from_rgb(31, 41, 55),
                            Color32::from_rgb(167, 139, 250),
                        );
                    });
                });

                ui.add_space(10.0);

                // Upload & Download live meters side-by-side
                ui.columns(2, |cols| {
                    egui::Frame::none()
                        .fill(subcard_bg)
                        .stroke(Stroke::new(1.0, Color32::from_rgb(28, 42, 62)))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(12.0, 10.0))
                        .show(&mut cols[0], |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("▲ UPLOAD THROUGHPUT")
                                        .font(FontId::proportional(12.0))
                                        .color(Color32::from_rgb(148, 163, 184)),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            RichText::new(format!(
                                                "{:.1} MiB/s",
                                                snap.frame.up_mib_s
                                            ))
                                            .font(FontId::monospace(18.0))
                                            .strong()
                                            .color(Color32::from_rgb(34, 211, 238)),
                                        );
                                    },
                                );
                            });
                            ui.add_space(6.0);
                            let up_norm = (snap.frame.up_mib_s as f32 / 600.0).clamp(0.0, 1.0);
                            ui.add(
                                ProgressBar::new(up_norm)
                                    .fill(Color32::from_rgb(6, 182, 212))
                                    .text(format!(
                                        "Peak {:.1} MiB/s • Link Ceiling 600 MiB/s",
                                        snap.peak_up_mib_s
                                    )),
                            );
                            ui.add_space(6.0);
                            draw_sparkline(
                                ui,
                                &snap.up_history,
                                600.0,
                                Color32::from_rgb(34, 211, 238),
                            );
                        });

                    egui::Frame::none()
                        .fill(subcard_bg)
                        .stroke(Stroke::new(1.0, Color32::from_rgb(28, 42, 62)))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(12.0, 10.0))
                        .show(&mut cols[1], |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("▼ DOWNLOAD THROUGHPUT")
                                        .font(FontId::proportional(12.0))
                                        .color(Color32::from_rgb(148, 163, 184)),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            RichText::new(format!(
                                                "{:.1} MiB/s",
                                                snap.frame.down_mib_s
                                            ))
                                            .font(FontId::monospace(18.0))
                                            .strong()
                                            .color(Color32::from_rgb(96, 165, 250)),
                                        );
                                    },
                                );
                            });
                            ui.add_space(6.0);
                            let down_norm =
                                (snap.frame.down_mib_s as f32 / 1200.0).clamp(0.0, 1.0);
                            ui.add(
                                ProgressBar::new(down_norm)
                                    .fill(Color32::from_rgb(59, 130, 246))
                                    .text(format!(
                                        "Peak {:.1} MiB/s • Link Ceiling 1200 MiB/s",
                                        snap.peak_down_mib_s
                                    )),
                            );
                            ui.add_space(6.0);
                            draw_sparkline(
                                ui,
                                &snap.down_history,
                                1200.0,
                                Color32::from_rgb(96, 165, 250),
                            );
                        });
                });

                ui.add_space(10.0);

                // Overall batch transfer progress bar
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Active Sync Pipeline:")
                            .font(FontId::proportional(12.5))
                            .color(Color32::from_rgb(203, 213, 225)),
                    );
                    ui.add(
                        ProgressBar::new(snap.frame.progress.clamp(0.0, 1.0))
                            .fill(Color32::from_rgb(16, 185, 129))
                            .text(format!(
                                "{:.1}% Complete  •  {} In-Flight VAES Chunks  •  IPC Frames Rx: {}",
                                snap.frame.progress * 100.0,
                                snap.frame.active_chunks,
                                snap.frames_received
                            )),
                    );
                });

                ui.add_space(12.0);

                // 3-Provider Multi-Cloud Quota Cards
                ui.columns(3, |cols| {
                    let gdrive_used = 842.4 + (snap.frame.progress * 6.8);
                    render_cloud_quota_card(
                        &mut cols[0],
                        "Google Drive",
                        "Workspace Pool • TLS 1.3",
                        gdrive_used,
                        2048.0,
                        Color32::from_rgb(52, 211, 153),
                    );

                    let onedrive_used = 518.9 + (snap.frame.progress * 4.1);
                    render_cloud_quota_card(
                        &mut cols[1],
                        "OneDrive",
                        "Graph Storage • HTTP/3",
                        onedrive_used,
                        1024.0,
                        Color32::from_rgb(56, 189, 248),
                    );

                    let s3_used = 1420.0 + (snap.frame.progress * 9.5);
                    render_cloud_quota_card(
                        &mut cols[2],
                        "Amazon S3",
                        "Direct NVMe->S3 • KMS",
                        s3_used,
                        4096.0,
                        Color32::from_rgb(251, 191, 36),
                    );
                });
            });
    }

    fn render_settings_panel(&mut self, ui: &mut egui::Ui) {
        let card_bg = Color32::from_rgb(18, 24, 38);
        let border = Color32::from_rgb(34, 46, 68);

        egui::Frame::none()
            .fill(card_bg)
            .stroke(Stroke::new(1.0, border))
            .rounding(Rounding::same(10.0))
            .inner_margin(Margin::symmetric(16.0, 14.0))
            .show(ui, |ui| {
                ui.label(
                    RichText::new("Vault Settings & Cryptographic Routing Policy")
                        .font(FontId::proportional(16.0))
                        .strong()
                        .color(Color32::from_rgb(236, 242, 252)),
                );
                ui.add_space(10.0);

                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new("Routing Policy:")
                            .font(FontId::proportional(13.5))
                            .color(Color32::from_rgb(203, 213, 225)),
                    );
                    for policy in [
                        RoutingPolicy::Targeted,
                        RoutingPolicy::MirroredRaid1,
                        RoutingPolicy::QuotaPooled,
                    ] {
                        let selected = self.routing_policy == policy;
                        let btn = egui::Button::new(
                            RichText::new(policy.label())
                                .strong()
                                .color(if selected {
                                    Color32::from_rgb(16, 24, 39)
                                } else {
                                    Color32::from_rgb(226, 232, 240)
                                }),
                        )
                        .fill(if selected {
                            Color32::from_rgb(56, 189, 248)
                        } else {
                            Color32::from_rgb(30, 41, 59)
                        })
                        .rounding(Rounding::same(6.0));
                        if ui.add(btn).clicked() {
                            self.routing_policy = policy;
                        }
                    }
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(self.routing_policy.description())
                            .font(FontId::proportional(12.0))
                            .color(Color32::from_rgb(148, 163, 184)),
                    );
                });

                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("NVMe Staging Cache Limit:")
                            .font(FontId::proportional(13.5))
                            .color(Color32::from_rgb(203, 213, 225)),
                    );
                    ui.spacing_mut().slider_width = 280.0;
                    ui.add(
                        Slider::new(&mut self.cache_limit_gib, 2.0..=128.0)
                            .suffix(" GiB")
                            .fixed_decimals(1),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (btn_label, btn_fill, text_col) = if self.vault_locked {
                            (
                                "Unlock Vault (Z:\\ZeroVault)",
                                Color32::from_rgb(16, 185, 129),
                                Color32::from_rgb(8, 22, 18),
                            )
                        } else {
                            (
                                "Lock Vault",
                                Color32::from_rgb(220, 38, 38),
                                Color32::from_rgb(255, 245, 245),
                            )
                        };
                        let lock_btn = egui::Button::new(
                            RichText::new(btn_label)
                                .font(FontId::proportional(13.5))
                                .strong()
                                .color(text_col),
                        )
                        .fill(btn_fill)
                        .min_size(Vec2::new(170.0, 32.0))
                        .rounding(Rounding::same(7.0));

                        if ui.add(lock_btn).clicked() {
                            self.vault_locked = !self.vault_locked;
                        }
                    });
                });
            });
    }

    fn snapshot_ipc(&self) -> TelemetrySnapshot {
        let guard = self.ipc.state.lock();
        TelemetrySnapshot {
            frame: guard.latest.clone(),
            frames_received: guard.frames_received,
            connected: guard.connected,
            pipe_name: guard.pipe_name.clone(),
            ipc_mode: guard.ipc_mode.clone(),
            peak_up_mib_s: guard.peak_up_mib_s,
            peak_down_mib_s: guard.peak_down_mib_s,
            up_history: guard.up_history.iter().copied().collect(),
            down_history: guard.down_history.iter().copied().collect(),
        }
    }

    /// Invoked inside `App::on_exit` immediately after `swap_buffers` / `surface.present()`
    /// and BEFORE GPU context / OS window teardown so resident RAM includes full GPU resources.
    fn capture_exit_telemetry(&mut self) {
        if self.exit_captured {
            return;
        }
        self.exit_captured = true;
        let exit_qpc = qpc_now();
        let mem = sample_current_process_memory();
        let snap = self.snapshot_ipc();
        self.ipc.shutdown();

        match self.bench_mode {
            BenchMode::Interactive => {}
            BenchMode::Cold {
                main_entry_qpc,
                ipc_ready_qpc,
                spawn_qpc,
            } => {
                let res = ColdBenchResult {
                    mode: "bench-cold".to_owned(),
                    backend: self.backend_name.clone(),
                    gpu_adapter: self.gpu_adapter.clone(),
                    ipc_pipe: snap.pipe_name,
                    ipc_mode: snap.ipc_mode,
                    initial_ipc_seq: snap.frame.seq,
                    ipc_connect_first_frame_ms: qpc_elapsed_ms(main_entry_qpc, ipc_ready_qpc),
                    internal_cold_start_ms: qpc_elapsed_ms(main_entry_qpc, exit_qpc),
                    external_cold_start_ms: spawn_qpc.map(|sq| qpc_elapsed_ms(sq, exit_qpc)),
                    frame1_update_cpu_ms: round3(self.frame1_update_cpu_ms),
                    memory: mem,
                };
                self.output_slot.lock().cold = Some(res);
            }
            BenchMode::Fps60 {
                main_entry_qpc,
                target_frames,
            } => {
                let start_qpc = self.stream_start_qpc.unwrap_or(main_entry_qpc);
                let elapsed_ms = qpc_elapsed_ms(start_qpc, exit_qpc);
                let fps = if elapsed_ms > 0.0 {
                    round3((self.ipc_driven_frames as f64 * 1000.0) / elapsed_ms)
                } else {
                    0.0
                };
                let res = Fps60BenchResult {
                    mode: "bench-60fps".to_owned(),
                    backend: self.backend_name.clone(),
                    gpu_adapter: self.gpu_adapter.clone(),
                    ipc_pipe: snap.pipe_name,
                    ipc_mode: snap.ipc_mode,
                    target_ipc_frames: target_frames,
                    rendered_ipc_frames: self.ipc_driven_frames,
                    total_gpu_frames: self.total_gpu_frames,
                    elapsed_wall_ms: elapsed_ms,
                    achieved_fps: fps,
                    frame_pacing_ms: DistributionStats::from_samples(&self.frame_pacing_samples_ms),
                    frame_render_cpu_ms: DistributionStats::from_samples(
                        &self.frame_render_samples_ms,
                    ),
                    memory: mem,
                };
                self.output_slot.lock().fps60 = Some(res);
            }
        }
    }
}

struct TelemetrySnapshot {
    frame: TelemetryFrame,
    frames_received: u64,
    connected: bool,
    pipe_name: String,
    ipc_mode: String,
    peak_up_mib_s: f64,
    peak_down_mib_s: f64,
    up_history: Vec<f32>,
    down_history: Vec<f32>,
}

impl eframe::App for ZeroVaultApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        let update_start_qpc = qpc_now();
        self.total_gpu_frames += 1;

        if let Some(prev_cpu_sec) = frame.info().cpu_usage {
            self.frame_render_samples_ms
                .push(round3(prev_cpu_sec as f64 * 1000.0));
        }

        let snap = self.snapshot_ipc();

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_rgb(11, 15, 23))
                    .inner_margin(Margin::symmetric(16.0, 14.0)),
            )
            .show(ctx, |ui| {
                self.render_header(ui, &snap);
                ui.add_space(12.0);

                match self.active_tab {
                    ActiveTab::Unified => {
                        self.render_transfer_meter_panel(ui, &snap);
                        ui.add_space(12.0);
                        self.render_settings_panel(ui);
                    }
                    ActiveTab::VaultStatus => {
                        self.render_transfer_meter_panel(ui, &snap);
                    }
                    ActiveTab::Settings => {
                        self.render_settings_panel(ui);
                    }
                }
            });

        let update_end_qpc = qpc_now();
        let update_cpu_ms = qpc_elapsed_ms(update_start_qpc, update_end_qpc);
        if self.total_gpu_frames == 1 {
            self.frame1_update_cpu_ms = update_cpu_ms;
        }

        match self.bench_mode {
            BenchMode::Interactive => {}
            BenchMode::Cold { .. } => {
                // Ensure Frame #1 has live Named Pipe data (`seq >= 1`), then trigger Close
                // which executes AFTER GPU paint + swap_buffers!
                if snap.frame.seq >= 1 && self.total_gpu_frames >= 1 {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                } else {
                    ctx.request_repaint();
                }
            }
            BenchMode::Fps60 { target_frames, .. } => {
                let now_qpc = qpc_now();
                if self.total_gpu_frames < 2 {
                    // Allow initial Win32 WM_SHOWWINDOW / DWM surface map pass to finish before
                    // timing 300 steady-state 60 Hz IPC frames (5.00 seconds).
                    ctx.request_repaint();
                } else if self.stream_start_qpc.is_none() {
                    self.stream_start_qpc = Some(now_qpc);
                    self.prev_ipc_frame_qpc = Some(now_qpc);
                    self.last_rendered_seq = snap.frame.seq;
                    self.ipc_driven_frames = 1;
                } else if snap.frame.seq > self.last_rendered_seq {
                    if let Some(prev_qpc) = self.prev_ipc_frame_qpc {
                        let dt_ms = qpc_elapsed_ms(prev_qpc, now_qpc);
                        self.frame_pacing_samples_ms.push(dt_ms);
                    }
                    self.prev_ipc_frame_qpc = Some(now_qpc);
                    self.last_rendered_seq = snap.frame.seq;
                    self.ipc_driven_frames += 1;
                }

                if self.ipc_driven_frames >= target_frames {
                    if self.frame_render_samples_ms.is_empty() {
                        self.frame_render_samples_ms.push(update_cpu_ms);
                    }
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
    }

    #[cfg(feature = "backend-glow")]
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.capture_exit_telemetry();
    }

    #[cfg(not(feature = "backend-glow"))]
    fn on_exit(&mut self) {
        self.capture_exit_telemetry();
    }
}

fn configure_dark_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = Color32::from_rgb(11, 15, 23);
    visuals.window_fill = Color32::from_rgb(15, 21, 33);
    visuals.extreme_bg_color = Color32::from_rgb(8, 11, 18);
    visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(22, 30, 46);
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(28, 38, 58);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(38, 52, 78);
    visuals.widgets.active.bg_fill = Color32::from_rgb(14, 165, 233);
    visuals.selection.bg_fill = Color32::from_rgb(14, 116, 144);
    ctx.set_visuals(visuals);
}

fn badge_pill(ui: &mut egui::Ui, text: &str, bg: Color32, fg: Color32) {
    egui::Frame::none()
        .fill(bg)
        .stroke(Stroke::new(1.0, fg.gamma_multiply(0.35)))
        .rounding(Rounding::same(6.0))
        .inner_margin(Margin::symmetric(8.0, 3.0))
        .show(ui, |ui| {
            ui.label(
                RichText::new(text)
                    .font(FontId::proportional(11.5))
                    .strong()
                    .color(fg),
            );
        });
}

fn render_cloud_quota_card(
    ui: &mut egui::Ui,
    provider: &str,
    subtitle: &str,
    used_gib: f32,
    total_gib: f32,
    accent: Color32,
) {
    let ratio = (used_gib / total_gib.max(1.0)).clamp(0.0, 1.0);
    egui::Frame::none()
        .fill(Color32::from_rgb(13, 18, 29))
        .stroke(Stroke::new(1.0, Color32::from_rgb(30, 42, 62)))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::symmetric(12.0, 10.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(provider)
                        .font(FontId::proportional(14.0))
                        .strong()
                        .color(Color32::from_rgb(241, 245, 249)),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("{:.1}%", ratio * 100.0))
                            .font(FontId::monospace(12.0))
                            .color(accent),
                    );
                });
            });
            ui.label(
                RichText::new(subtitle)
                    .font(FontId::proportional(11.0))
                    .color(Color32::from_rgb(148, 163, 184)),
            );
            ui.add_space(6.0);
            ui.add(
                ProgressBar::new(ratio)
                    .fill(accent)
                    .text(format!("{used_gib:.1} / {total_gib:.0} GiB")),
            );
        });
}

fn draw_sparkline(ui: &mut egui::Ui, samples: &[f32], max_scale: f32, color: Color32) {
    let desired = Vec2::new(ui.available_width().max(120.0), 34.0);
    let (rect, _) = ui.allocate_exact_size(desired, egui::Sense::hover());
    let painter = ui.painter_at(rect);

    painter.rect_filled(rect, 4.0, Color32::from_rgb(9, 13, 22));
    painter.rect_stroke(rect, 4.0, Stroke::new(1.0, Color32::from_rgb(24, 34, 52)));

    if samples.len() < 2 {
        return;
    }
    let n = samples.len();
    let step_x = rect.width() / (n.saturating_sub(1).max(1) as f32);
    let points: Vec<Pos2> = samples
        .iter()
        .enumerate()
        .map(|(i, &val)| {
            let norm = (val / max_scale.max(1.0)).clamp(0.0, 1.0);
            let x = rect.left() + (i as f32) * step_x;
            let y = rect.bottom() - 3.0 - norm * (rect.height() - 6.0);
            Pos2::new(x, y)
        })
        .collect();

    painter.add(egui::Shape::line(points, Stroke::new(1.6, color)));
}

#[allow(unused_variables)]
fn detect_gpu_adapter_string(cc: &eframe::CreationContext<'_>) -> String {
    #[cfg(feature = "backend-wgpu")]
    {
        if let Some(ref rs) = cc.wgpu_render_state {
            let info = rs.adapter.get_info();
            return format!("{} ({:?})", info.name, info.backend);
        }
    }
    #[cfg(feature = "backend-glow")]
    {
        if let Some(ref gl) = cc.gl {
            use eframe::glow::HasContext;
            let renderer = unsafe { gl.get_parameter_string(eframe::glow::RENDERER) };
            let version = unsafe { gl.get_parameter_string(eframe::glow::VERSION) };
            return format!("{renderer} [{version}]");
        }
    }
    "Unknown GPU Adapter".to_owned()
}

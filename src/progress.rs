//! Shared progress display formatting.

use crate::dumper::{ProgressInfo, ProgressStage};

#[derive(Clone, Debug, Default)]
pub struct ProgressDisplay {
    pub stage: String,
    pub step: String,
    pub progress: String,
    pub metrics: Vec<(&'static str, String)>,
}

impl ProgressDisplay {
    pub fn metrics_text(&self) -> String {
        self.metrics
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("  ")
    }

    pub fn compact(&self) -> String {
        let metrics = self.metrics_text();
        if metrics.is_empty() {
            format!("{:<26} | {:<24} | {}", self.stage, self.step, self.progress)
        } else {
            format!(
                "{:<26} | {:<24} | {:<18} | {}",
                self.stage, self.step, self.progress, metrics
            )
        }
    }
}

pub fn progress_percent(info: &ProgressInfo) -> f64 {
    if info.stage == ProgressStage::ScanningSection && info.total_bytes > 0 {
        return (info.bytes_processed as f64 / info.total_bytes as f64) * 100.0;
    }
    if info.total > 0 {
        return (info.current as f64 / info.total as f64) * 100.0;
    }
    0.0
}

pub fn progress_display(info: &ProgressInfo) -> ProgressDisplay {
    match info.stage {
        ProgressStage::ScanningSection => ProgressDisplay {
            stage: info.stage.name().to_string(),
            step: info
                .current_item
                .clone()
                .unwrap_or_else(|| "sections".to_string()),
            progress: format_bytes_progress(info.bytes_processed, info.total_bytes),
            metrics: vec![("ptrs", info.pointers_found.to_string())],
        },
        ProgressStage::CreatingStubs => stub_progress_display(info),
        ProgressStage::ProtectingExceptionData => eh_progress_display(info),
        ProgressStage::ApplyingFixups => ProgressDisplay {
            stage: info.stage.name().to_string(),
            step: info
                .current_item
                .clone()
                .unwrap_or_else(|| "heap pointer fixups".to_string()),
            progress: format_count_progress(info.current, info.total),
            metrics: vec![
                ("applied", info.fixups_applied.to_string()),
                ("skipped", info.fixups_skipped.to_string()),
                ("protected_eh", info.protected_fixups_skipped.to_string()),
            ],
        },
        ProgressStage::AnalyzingMetadata | ProgressStage::BuildingMetadata => ProgressDisplay {
            stage: info.stage.name().to_string(),
            step: info.current_item.clone().unwrap_or_default(),
            progress: format_count_progress(info.current, info.total),
            metrics: Vec::new(),
        },
        ProgressStage::Devirtualizing => devirt_progress_display(info),
        _ => ProgressDisplay {
            stage: info.stage.name().to_string(),
            step: info.current_item.clone().unwrap_or_default(),
            progress: format_count_progress(info.current, info.total),
            metrics: Vec::new(),
        },
    }
}

fn stub_progress_display(info: &ProgressInfo) -> ProgressDisplay {
    let Some(stub) = info.stub_debug else {
        return ProgressDisplay {
            stage: info.stage.name().to_string(),
            step: "heap pointers".to_string(),
            progress: format_count_progress(info.current, info.total),
            metrics: vec![("stubs", info.stubs_created.to_string())],
        };
    };

    let mut metrics = vec![
        ("stubs", stub.created.to_string()),
        ("dup", stub.already_visited.to_string()),
        ("invalid", stub.invalid_heap_ptr.to_string()),
        ("no_vfptr", stub.no_vfptr_found.to_string()),
        ("outside", stub.vtable_not_in_module.to_string()),
    ];
    if stub.recursive_discovered > 0 {
        metrics.push(("recursive", stub.recursive_discovered.to_string()));
    }
    if stub.current_rva != 0 {
        metrics.push(("rva", format_hex(stub.current_rva as u64)));
    }
    if stub.current_heap_addr != 0 {
        metrics.push(("heap", format_hex(stub.current_heap_addr)));
    }

    ProgressDisplay {
        stage: info.stage.name().to_string(),
        step: stub.phase.to_string(),
        progress: format_count_progress(stub.current, stub.total),
        metrics,
    }
}

fn eh_progress_display(info: &ProgressInfo) -> ProgressDisplay {
    let Some(eh) = info.eh_progress else {
        return ProgressDisplay {
            stage: info.stage.name().to_string(),
            step: info.current_item.clone().unwrap_or_default(),
            progress: format_count_progress(info.current, info.total),
            metrics: Vec::new(),
        };
    };

    ProgressDisplay {
        stage: info.stage.name().to_string(),
        step: eh.phase.to_string(),
        progress: format_count_progress(eh.current, eh.total),
        metrics: vec![
            ("ranges", eh.protected_ranges.to_string()),
            ("protected", format_bytes(eh.protected_bytes)),
            ("unwind", eh.unwind_infos.to_string()),
        ],
    }
}

fn devirt_progress_display(info: &ProgressInfo) -> ProgressDisplay {
    let Some(devirt) = info.devirt_progress.as_ref() else {
        return ProgressDisplay {
            stage: info.stage.name().to_string(),
            step: info
                .current_item
                .clone()
                .unwrap_or_else(|| "starting".to_string()),
            progress: format_count_progress(info.current, info.total),
            metrics: Vec::new(),
        };
    };

    ProgressDisplay {
        stage: info.stage.name().to_string(),
        step: devirt.phase.to_string(),
        progress: format_count_progress(devirt.current, devirt.total),
        metrics: vec![
            ("instr", devirt.stats.instructions_scanned.to_string()),
            ("sites", devirt.stats.vcalls_detected.to_string()),
            (
                "global",
                devirt.stats.global_indirect_calls_detected.to_string(),
            ),
            ("resolved", devirt.stats.vcalls_resolved.to_string()),
            ("patched", devirt.stats.patches_applied.to_string()),
            ("skipped", devirt.stats.patches_skipped.to_string()),
            ("thunks", devirt.stats.thunks_created.to_string()),
        ],
    }
}

fn format_count_progress(current: usize, total: usize) -> String {
    if total == 0 {
        String::new()
    } else {
        format!("{current}/{total}")
    }
}

fn format_bytes_progress(current: usize, total: usize) -> String {
    if total == 0 {
        format_bytes(current)
    } else {
        format!("{}/{}", format_bytes(current), format_bytes(total))
    }
}

fn format_bytes(bytes: usize) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes as usize)
    }
}

fn format_hex(value: u64) -> String {
    format!("0x{value:X}")
}

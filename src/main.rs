// Defender Control — a small Windows GUI to enable/disable Windows Defender,
// add Defender exclusions, detect/uninstall other antivirus, and unblock a
// program via the firewall.
//
// Mechanism: toggles the Group Policy registry values that gate Microsoft
// Defender's real-time / antispyware protection (HKLM; needs admin — the
// embedded manifest forces a UAC prompt). The Advanced tab additionally drives
// Set-MpPreference and the WinDefend service for a harder disable.
//
// Honest limitations (shown in the UI): if Tamper Protection is ON, Windows
// reverts these changes and Set-MpPreference / exclusions are blocked — it
// can't be disabled programmatically by design. The WinDefend service is
// protected; stop/disable is often refused even for admins.
//
// Works on Windows 10 and Windows 11 (same registry surface on both).

// Hide the console window in release builds; keep it in debug for logging.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use egui::{Color32, RichText};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use winreg::HKEY;
use winreg::RegKey;
use winreg::enums::*;

// --- Registry locations -----------------------------------------------------

const POLICY_DEFENDER: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender";
const POLICY_RTP: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection";
const DEFENDER_FEATURES: &str = r"SOFTWARE\Microsoft\Windows Defender\Features";
const WINDOWS_NT_CURRENT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

const UNINSTALL_KEYS: &[(HKEY, &str)] = &[
    (
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
    (
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
    (
        HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
];

const RTP_VALUES: &[&str] = &[
    "DisableRealtimeMonitoring",
    "DisableBehaviorMonitoring",
    "DisableOnAccessProtection",
    "DisableScanOnRealtimeEnable",
    "DisableIOAVProtection",
];

const DEFENDER_SERVICES: &[&str] = &["WinDefend", "WdNisSvc"];

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// GitHub repo used for the built-in update check.
const REPO: &str = "RealSlimShady2000/DefenderControl420";

const LOGO_PNG: &[u8] =
    include_bytes!("../icons and logo/defendercontrol420-shield-transparent-v2-256.png");

const KNOWN_AV: &[&str] = &[
    "kaspersky", "mcafee", "avast", "avg ", "norton", "symantec", "bitdefender", "eset", "nod32",
    "malwarebytes", "avira", "trend micro", "webroot", "sophos", "f-secure", "panda security",
    "panda dome", "panda free", "comodo", "qihoo", "360 total security", "bullguard", "g data",
    "gdata", "vipre", "zonealarm", "ad-aware", "adaware", "emsisoft", "total av", "totalav",
    "pc matic", "quick heal", "k7 ", "dr.web", "drweb", "rising antivirus", "baidu anti",
    "forticlient", "crowdstrike", "sentinelone", "cylance", "carbon black", "immunet", "clamwin",
    "hitmanpro", "superantispyware", "spyhunter", "iobit malware", "nano antivirus", "max secure",
    "protegent", "zillya", "total defense", "365 total security",
];

// --- Theme colours -----------------------------------------------------------

const TEXT: Color32 = Color32::from_rgb(0xE6, 0xED, 0xF3);
const MUTED: Color32 = Color32::from_rgb(0x9D, 0xA7, 0xB3);
const ACCENT: Color32 = Color32::from_rgb(0x3B, 0x9E, 0xFF);
const GREEN: Color32 = Color32::from_rgb(0x3F, 0xB9, 0x50);
const RED: Color32 = Color32::from_rgb(0xE5, 0x6B, 0x6B);
const ORANGE: Color32 = Color32::from_rgb(0xE3, 0xA1, 0x2F);
const PANEL_BG: Color32 = Color32::from_rgb(0x0D, 0x11, 0x17);
const CARD_BG: Color32 = Color32::from_rgb(0x17, 0x1D, 0x26);
const CARD_BORDER: Color32 = Color32::from_rgb(0x2A, 0x31, 0x3D);
const FIELD_BG: Color32 = Color32::from_rgb(0x0A, 0x0E, 0x13);
const BTN_GREEN: Color32 = Color32::from_rgb(0x24, 0x8A, 0x3A);
const BTN_RED: Color32 = Color32::from_rgb(0xC4, 0x3B, 0x33);
const BANNER_GREEN: Color32 = Color32::from_rgb(0x1B, 0x6E, 0x33);
const BANNER_RED: Color32 = Color32::from_rgb(0x8E, 0x29, 0x2E);

// --- Small process helpers ---------------------------------------------------

fn timestamp() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

fn ps_quote(s: &str) -> String {
    s.replace('\'', "''")
}

fn version_label() -> String {
    let mut parts = env!("CARGO_PKG_VERSION").split('.');
    let brand = parts.next().unwrap_or("420");
    let major = parts.next().unwrap_or("1");
    let minor = parts.next().unwrap_or("0");
    if minor == "0" {
        format!("v{brand}.{major}")
    } else {
        format!("v{brand}.{major}.{minor}")
    }
}

fn run_powershell(script: &str) -> Result<String, String> {
    let out = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if err.is_empty() {
            format!("{}", out.status)
        } else {
            err.lines().next().unwrap_or(&err).to_string()
        })
    }
}

fn sc_summary(args: &[&str]) -> String {
    match Command::new("sc")
        .creation_flags(CREATE_NO_WINDOW)
        .args(args)
        .output()
    {
        Ok(o) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            let line = combined
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .unwrap_or("")
                .to_string();
            if o.status.success() && !line.to_lowercase().contains("fail") {
                if line.is_empty() { "OK".to_owned() } else { line }
            } else if line.is_empty() {
                format!("failed ({})", o.status)
            } else {
                line
            }
        }
        Err(e) => format!("could not run sc: {e}"),
    }
}

// --- Defender registry operations -------------------------------------------

fn disable_defender() -> std::io::Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (defender, _) = hklm.create_subkey(POLICY_DEFENDER)?;
    defender.set_value("DisableAntiSpyware", &1u32)?;
    defender.set_value("DisableAntiVirus", &1u32)?;
    let (rtp, _) = hklm.create_subkey(POLICY_RTP)?;
    for value in RTP_VALUES {
        rtp.set_value(value, &1u32)?;
    }
    Ok(())
}

fn enable_defender() -> std::io::Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(defender) = hklm.open_subkey_with_flags(POLICY_DEFENDER, KEY_ALL_ACCESS) {
        let _ = defender.delete_value("DisableAntiSpyware");
        let _ = defender.delete_value("DisableAntiVirus");
    }
    if let Ok(rtp) = hklm.open_subkey_with_flags(POLICY_RTP, KEY_ALL_ACCESS) {
        for value in RTP_VALUES {
            let _ = rtp.delete_value(value);
        }
    }
    Ok(())
}

fn defender_is_disabled() -> bool {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let anti_spyware = hklm
        .open_subkey(POLICY_DEFENDER)
        .ok()
        .and_then(|k| k.get_value::<u32, _>("DisableAntiSpyware").ok())
        .unwrap_or(0);
    let realtime = hklm
        .open_subkey(POLICY_RTP)
        .ok()
        .and_then(|k| k.get_value::<u32, _>("DisableRealtimeMonitoring").ok())
        .unwrap_or(0);
    anti_spyware == 1 || realtime == 1
}

fn tamper_protection_on() -> Option<bool> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let features = hklm.open_subkey(DEFENDER_FEATURES).ok()?;
    let value: u32 = features.get_value("TamperProtection").ok()?;
    Some(value == 5)
}

/// Authoritative live Defender state via Get-MpComputerStatus (needs admin).
/// This reflects what Defender is *actually* doing, regardless of whether the
/// Windows Security UI page is still browsable (it stays open on Win10 22H2).
fn defender_live_status() -> Result<String, String> {
    run_powershell(
        "$s = Get-MpComputerStatus -ErrorAction Stop; \
         'Real-time: ' + $(if ($s.RealTimeProtectionEnabled) {'ON'} else {'OFF'}) + \
         '   Antivirus: ' + $(if ($s.AntivirusEnabled) {'ON'} else {'OFF'}) + \
         '   Tamper: ' + $(if ($s.IsTamperProtected) {'ON'} else {'OFF'})",
    )
}

fn is_elevated() -> bool {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags("SOFTWARE", KEY_WRITE)
        .is_ok()
}

// --- System detection --------------------------------------------------------

struct SysInfo {
    os: String,
    version: String,
    build: String,
    arch: String,
    compatible: bool,
}

fn detect_system() -> SysInfo {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cv = hklm.open_subkey(WINDOWS_NT_CURRENT);
    let sz = |key: &str| {
        cv.as_ref()
            .ok()
            .and_then(|c| c.get_value::<String, _>(key).ok())
    };
    let dw = |key: &str| cv.as_ref().ok().and_then(|c| c.get_value::<u32, _>(key).ok());

    let build_num: u32 = sz("CurrentBuildNumber")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let ubr = dw("UBR").unwrap_or(0);
    let version = sz("DisplayVersion").or_else(|| sz("ReleaseId")).unwrap_or_default();
    let product = sz("ProductName").unwrap_or_else(|| "Windows".to_owned());
    let os = if build_num >= 22000 {
        product.replace("Windows 10", "Windows 11")
    } else {
        product
    };

    let raw_arch = std::env::var("PROCESSOR_ARCHITEW6432")
        .ok()
        .or_else(|| std::env::var("PROCESSOR_ARCHITECTURE").ok())
        .unwrap_or_default();
    let arch = match raw_arch.to_uppercase().as_str() {
        "AMD64" => "x64".to_owned(),
        "ARM64" => "ARM64".to_owned(),
        "X86" => "32-bit (x86)".to_owned(),
        s if !s.is_empty() => s.to_lowercase(),
        _ => "unknown".to_owned(),
    };

    let build = if ubr > 0 {
        format!("{build_num}.{ubr}")
    } else {
        build_num.to_string()
    };

    SysInfo {
        os,
        version,
        build,
        arch,
        compatible: build_num >= 10240,
    }
}

// --- Defender exclusions -----------------------------------------------------

fn defender_list_exclusions() -> Vec<String> {
    match run_powershell("(Get-MpPreference).ExclusionPath") {
        Ok(out) => out
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with("N/A"))
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn defender_add_exclusion(path: &str) -> Result<(), String> {
    run_powershell(&format!(
        "Add-MpPreference -ExclusionPath '{}' -ErrorAction Stop",
        ps_quote(path)
    ))
    .map(|_| ())
}

fn defender_remove_exclusion(path: &str) -> Result<(), String> {
    run_powershell(&format!(
        "Remove-MpPreference -ExclusionPath '{}' -ErrorAction Stop",
        ps_quote(path)
    ))
    .map(|_| ())
}

// --- Aggressive disable / full re-enable -------------------------------------

fn aggressive_disable() -> Vec<String> {
    let mut log = Vec::new();
    match disable_defender() {
        Ok(()) => log.push("Policy keys set (antispyware + real-time).".to_owned()),
        Err(e) => log.push(format!("Policy keys failed: {e}")),
    }
    let script = "Set-MpPreference -DisableRealtimeMonitoring $true \
        -DisableBehaviorMonitoring $true -DisableIOAVProtection $true \
        -DisableScriptScanning $true -DisableArchiveScanning $true \
        -MAPSReporting 0 -SubmitSamplesConsent 2 -ErrorAction Stop";
    match run_powershell(script) {
        Ok(_) => log.push("Set-MpPreference: live protections disabled.".to_owned()),
        Err(e) => log.push(format!("Set-MpPreference failed (Tamper Protection on?): {e}")),
    }
    for svc in DEFENDER_SERVICES {
        log.push(format!("sc stop {svc}: {}", sc_summary(&["stop", svc])));
        log.push(format!(
            "sc config {svc} start=disabled: {}",
            sc_summary(&["config", svc, "start=", "disabled"])
        ));
    }
    log
}

fn full_reenable() -> Vec<String> {
    let mut log = Vec::new();
    match enable_defender() {
        Ok(()) => log.push("Policy keys removed.".to_owned()),
        Err(e) => log.push(format!("Policy key removal failed: {e}")),
    }
    let script = "Set-MpPreference -DisableRealtimeMonitoring $false \
        -DisableBehaviorMonitoring $false -DisableIOAVProtection $false \
        -DisableScriptScanning $false -DisableArchiveScanning $false \
        -ErrorAction Stop";
    match run_powershell(script) {
        Ok(_) => log.push("Set-MpPreference: live protections re-enabled.".to_owned()),
        Err(e) => log.push(format!("Set-MpPreference failed: {e}")),
    }
    for svc in DEFENDER_SERVICES {
        log.push(format!(
            "sc config {svc} start=auto: {}",
            sc_summary(&["config", svc, "start=", "auto"])
        ));
        log.push(format!("sc start {svc}: {}", sc_summary(&["start", svc])));
    }
    log.push("A restart is recommended to fully restore the WinDefend service.".to_owned());
    log
}

// --- Other-antivirus detection ----------------------------------------------

#[derive(Clone)]
struct DetectedAv {
    name: String,
    uninstall: Option<String>,
    interactive: bool,
}

fn scan_installed_av() -> Vec<DetectedAv> {
    let mut found: Vec<DetectedAv> = Vec::new();
    for (hive, path) in UNINSTALL_KEYS {
        let Ok(root) = RegKey::predef(*hive).open_subkey(path) else {
            continue;
        };
        for sub in root.enum_keys().flatten() {
            let Ok(app) = root.open_subkey(&sub) else {
                continue;
            };
            let name: String = app.get_value("DisplayName").unwrap_or_default();
            if name.trim().is_empty() {
                continue;
            }
            let lname = name.to_lowercase();
            let is_av = KNOWN_AV.iter().any(|kw| lname.contains(kw));
            let is_ms_defender =
                lname.contains("windows defender") || lname.contains("microsoft defender");
            if !is_av || is_ms_defender {
                continue;
            }
            if found.iter().any(|a| a.name.eq_ignore_ascii_case(&name)) {
                continue;
            }
            let quiet = app
                .get_value::<String, _>("QuietUninstallString")
                .ok()
                .filter(|s| !s.trim().is_empty());
            let normal = app
                .get_value::<String, _>("UninstallString")
                .ok()
                .filter(|s| !s.trim().is_empty());
            let (uninstall, interactive) = match quiet {
                Some(q) => (Some(q), false),
                None => (normal, true),
            };
            found.push(DetectedAv {
                name,
                uninstall,
                interactive,
            });
        }
    }
    found
}

fn run_uninstall_string(s: &str) -> std::io::Result<()> {
    let s = s.trim();
    let (program, rest) = if let Some(stripped) = s.strip_prefix('"') {
        match stripped.split_once('"') {
            Some((exe, rest)) => (exe.to_string(), rest.trim().to_string()),
            None => (stripped.to_string(), String::new()),
        }
    } else {
        match s.split_once(' ') {
            Some((exe, rest)) => (exe.to_string(), rest.trim().to_string()),
            None => (s.to_string(), String::new()),
        }
    };
    let mut cmd = Command::new(program);
    if !rest.is_empty() {
        cmd.args(rest.split_whitespace());
    }
    cmd.spawn()?;
    Ok(())
}

// --- Firewall ----------------------------------------------------------------

fn add_firewall_rules(exe: &Path) -> std::io::Result<()> {
    if !exe.exists() {
        return Err(std::io::Error::other(format!(
            "file not found: {}",
            exe.display()
        )));
    }
    let path = exe.to_string_lossy();
    let stem = exe
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "Program".to_owned());
    for dir in ["in", "out"] {
        let status = Command::new("netsh")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name=Allow {stem} ({dir})"),
                &format!("dir={dir}"),
                "action=allow",
                &format!("program={path}"),
                "enable=yes",
                "profile=any",
            ])
            .status()?;
        if !status.success() {
            return Err(std::io::Error::other(format!("netsh failed ({status})")));
        }
    }
    Ok(())
}

fn relaunch_as_admin() {
    if let Ok(exe) = std::env::current_exe() {
        let path = exe.to_string_lossy().replace('\'', "''");
        let _ = Command::new("powershell")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "-NoProfile",
                "-Command",
                &format!("Start-Process -FilePath '{path}' -Verb RunAs"),
            ])
            .spawn();
        std::process::exit(0);
    }
}

// --- Auto-update (checks GitHub releases) ------------------------------------

#[derive(Clone)]
enum UpdateState {
    Checking,
    UpToDate,
    Available { tag: String, url: String },
    Downloading,
    Failed(String),
    Dismissed,
}

fn parse_ver(s: &str) -> Option<(u32, u32, u32)> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let mut it = s.split('.');
    let a = it.next()?.trim().parse().ok()?;
    let b = it.next().and_then(|x| x.trim().parse().ok()).unwrap_or(0);
    let c = it.next().and_then(|x| x.trim().parse().ok()).unwrap_or(0);
    Some((a, b, c))
}

/// Ask GitHub for the latest release and compare it to the running version.
fn check_for_update() -> UpdateState {
    let script = format!(
        "$ProgressPreference='SilentlyContinue'; \
         [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; \
         $r = Invoke-RestMethod -Uri 'https://api.github.com/repos/{REPO}/releases/latest' \
         -Headers @{{'User-Agent'='DefenderControl420'}} -ErrorAction Stop; \
         $a = ($r.assets | Where-Object {{ $_.name -like '*.exe' }} | \
         Select-Object -First 1).browser_download_url; \
         $r.tag_name + '|' + $a"
    );
    match run_powershell(&script) {
        Ok(out) => {
            let mut parts = out.splitn(2, '|');
            let tag = parts.next().unwrap_or_default().trim().to_string();
            let url = parts.next().unwrap_or_default().trim().to_string();
            match (parse_ver(&tag), parse_ver(env!("CARGO_PKG_VERSION"))) {
                (Some(remote), Some(local)) if remote > local && !url.is_empty() => {
                    UpdateState::Available { tag, url }
                }
                (Some(_), Some(_)) => UpdateState::UpToDate,
                _ => UpdateState::Failed("couldn't read version".to_owned()),
            }
        }
        Err(e) => UpdateState::Failed(e),
    }
}

/// Download the new exe, then hand off to a detached PowerShell script that
/// waits for this process to exit, swaps the exe in place, and relaunches it.
fn perform_update(url: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let target = exe.to_string_lossy().replace('\'', "''");
    let tmp = std::env::temp_dir().join("DefenderControl420.update.exe");
    let tmp_s = tmp.to_string_lossy().replace('\'', "''");

    run_powershell(&format!(
        "$ProgressPreference='SilentlyContinue'; \
         [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; \
         Invoke-WebRequest -Uri '{}' -OutFile '{tmp_s}' \
         -Headers @{{'User-Agent'='DefenderControl420'}} -ErrorAction Stop",
        url.replace('\'', "''")
    ))?;

    let updater = std::env::temp_dir().join("DefenderControl420.update.ps1");
    let pid = std::process::id();
    let script = format!(
        "try {{ Wait-Process -Id {pid} -Timeout 60 -ErrorAction SilentlyContinue }} catch {{}}\r\n\
         Start-Sleep -Milliseconds 600\r\n\
         Copy-Item -LiteralPath '{tmp_s}' -Destination '{target}' -Force\r\n\
         Remove-Item -LiteralPath '{tmp_s}' -Force -ErrorAction SilentlyContinue\r\n\
         Start-Process -FilePath '{target}'\r\n"
    );
    std::fs::write(&updater, script).map_err(|e| e.to_string())?;

    Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File"])
        .arg(&updater)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

// --- Styling helpers ---------------------------------------------------------

fn load_logo(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let icon = eframe::icon_data::from_png_bytes(LOGO_PNG).ok()?;
    let image =
        egui::ColorImage::from_rgba_unmultiplied([icon.width as usize, icon.height as usize], &icon.rgba);
    Some(ctx.load_texture("logo", image, egui::TextureOptions::LINEAR))
}

fn setup_style(ctx: &egui::Context) {
    use egui::{CornerRadius, Margin, Stroke};
    let mut style = (*ctx.global_style()).clone();
    let v = &mut style.visuals;
    v.dark_mode = true;
    v.override_text_color = Some(TEXT);
    v.panel_fill = PANEL_BG;
    v.window_fill = PANEL_BG;
    v.extreme_bg_color = FIELD_BG;
    v.faint_bg_color = CARD_BG;
    v.hyperlink_color = ACCENT;
    v.warn_fg_color = ORANGE;
    v.error_fg_color = RED;
    v.window_corner_radius = CornerRadius::same(10);
    v.menu_corner_radius = CornerRadius::same(8);
    v.selection.bg_fill = Color32::from_rgba_unmultiplied(0x3B, 0x9E, 0xFF, 0x66);
    v.selection.stroke = Stroke::new(1.0, ACCENT);

    let radius = CornerRadius::same(8);
    let border = Color32::from_rgb(0x2B, 0x33, 0x40);
    v.widgets.noninteractive.bg_fill = CARD_BG;
    v.widgets.noninteractive.weak_bg_fill = CARD_BG;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, border);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    v.widgets.noninteractive.corner_radius = radius;

    v.widgets.inactive.bg_fill = Color32::from_rgb(0x21, 0x29, 0x33);
    v.widgets.inactive.weak_bg_fill = Color32::from_rgb(0x21, 0x29, 0x33);
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, border);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    v.widgets.inactive.corner_radius = radius;

    v.widgets.hovered.bg_fill = Color32::from_rgb(0x2B, 0x34, 0x41);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x2B, 0x34, 0x41);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT);
    v.widgets.hovered.corner_radius = radius;

    v.widgets.active.bg_fill = Color32::from_rgb(0x2C, 0x77, 0xC0);
    v.widgets.active.weak_bg_fill = Color32::from_rgb(0x2C, 0x77, 0xC0);
    v.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    v.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    v.widgets.active.corner_radius = radius;

    v.widgets.open.bg_fill = Color32::from_rgb(0x21, 0x29, 0x33);
    v.widgets.open.weak_bg_fill = Color32::from_rgb(0x21, 0x29, 0x33);
    v.widgets.open.bg_stroke = Stroke::new(1.0, border);
    v.widgets.open.fg_stroke = Stroke::new(1.0, TEXT);
    v.widgets.open.corner_radius = radius;

    let s = &mut style.spacing;
    s.item_spacing = egui::vec2(8.0, 8.0);
    s.button_padding = egui::vec2(12.0, 7.0);
    s.menu_margin = Margin::same(8);
    s.indent = 16.0;

    ctx.set_global_style(style);
}

fn status_dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 5.0, color);
}

fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::NONE
        .fill(CARD_BG)
        .stroke(egui::Stroke::new(1.0, CARD_BORDER))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

fn step(ui: &mut egui::Ui, num: u32, text: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        ui.label(RichText::new(format!("{num}.")).strong().color(ACCENT));
        ui.label(RichText::new(text).color(TEXT));
    });
}

fn body(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(TEXT));
}

fn hint(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(MUTED).size(12.5));
}

// --- Application state -------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Exclusions,
    OtherAv,
    Firewall,
    Advanced,
}

/// Results from background worker threads, drained on the UI thread each frame.
enum Job {
    Log(String),
    Exclusions(Vec<String>),
    Refresh,
}

struct DefenderControlApp {
    sys: SysInfo,
    elevated: bool,
    disabled: bool,
    tamper: Option<bool>,
    active_tab: Tab,
    exclusion_path: String,
    exclusions: Vec<String>,
    exclusions_loaded: bool,
    av_scanned: bool,
    av_results: Vec<DetectedAv>,
    pending_uninstall: Option<DetectedAv>,
    firewall_exe_path: String,
    logs: Vec<String>,
    logo: Option<egui::TextureHandle>,
    update: Arc<Mutex<UpdateState>>,
    update_checking: Arc<AtomicBool>,
    busy: Arc<AtomicBool>,
    job_tx: Sender<Job>,
    job_rx: Receiver<Job>,
}

impl Default for DefenderControlApp {
    fn default() -> Self {
        let (job_tx, job_rx) = std::sync::mpsc::channel();
        let mut app = Self {
            sys: detect_system(),
            elevated: false,
            disabled: false,
            tamper: None,
            active_tab: Tab::Exclusions,
            exclusion_path: String::new(),
            exclusions: Vec::new(),
            exclusions_loaded: false,
            av_scanned: false,
            av_results: Vec::new(),
            pending_uninstall: None,
            firewall_exe_path: String::new(),
            logs: Vec::new(),
            logo: None,
            update: Arc::new(Mutex::new(UpdateState::Checking)),
            update_checking: Arc::new(AtomicBool::new(false)),
            busy: Arc::new(AtomicBool::new(false)),
            job_tx,
            job_rx,
        };
        app.refresh();
        app.log("Ready.");
        app
    }
}

impl DefenderControlApp {
    fn refresh(&mut self) {
        self.elevated = is_elevated();
        self.disabled = defender_is_disabled();
        self.tamper = tamper_protection_on();
    }

    fn log(&mut self, msg: impl Into<String>) {
        self.logs.push(format!("[{}]  {}", timestamp(), msg.into()));
        // Cap the log so it can't grow without bound over a long session.
        const MAX_LOGS: usize = 300;
        if self.logs.len() > MAX_LOGS {
            self.logs.drain(0..self.logs.len() - MAX_LOGS);
        }
    }

    /// Kick off a background update check (keeps the UI responsive).
    fn spawn_update_check(&self, ctx: &egui::Context) {
        if self.update_checking.swap(true, Ordering::SeqCst) {
            return; // a check is already in flight
        }
        *self.update.lock().unwrap() = UpdateState::Checking;
        let upd = self.update.clone();
        let flag = self.update_checking.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = check_for_update();
            *upd.lock().unwrap() = result;
            flag.store(false, Ordering::SeqCst);
            ctx.request_repaint();
        });
    }

    /// Run a slow (PowerShell / sc) action off the UI thread; only one job runs
    /// at a time. Results stream back via the channel and are drained per frame.
    fn spawn_job<F>(&self, ctx: &egui::Context, f: F)
    where
        F: FnOnce(&Sender<Job>) + Send + 'static,
    {
        if self.busy.swap(true, Ordering::SeqCst) {
            return; // a job is already running
        }
        let tx = self.job_tx.clone();
        let busy = self.busy.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            f(&tx);
            busy.store(false, Ordering::SeqCst);
            ctx.request_repaint();
        });
    }

    fn drain_jobs(&mut self) {
        while let Ok(job) = self.job_rx.try_recv() {
            match job {
                Job::Log(s) => self.log(s),
                Job::Exclusions(v) => {
                    self.exclusions = v;
                    self.exclusions_loaded = true;
                }
                Job::Refresh => self.refresh(),
            }
        }
    }

    /// Download + install the update in the background, then quit so the
    /// detached updater can swap the exe and relaunch it.
    fn start_update(&self, ctx: &egui::Context, url: String) {
        *self.update.lock().unwrap() = UpdateState::Downloading;
        let upd = self.update.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || match perform_update(&url) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                *upd.lock().unwrap() = UpdateState::Failed(format!("update failed: {e}"));
                ctx.request_repaint();
            }
        });
    }
}

impl eframe::App for DefenderControlApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_jobs();

        // Pinned activity log at the bottom.
        egui::Panel::bottom("activity_log")
            .resizable(false)
            .exact_size(132.0)
            .frame(egui::Frame::NONE.fill(PANEL_BG).inner_margin(egui::Margin::same(10)))
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Activity log").strong().color(TEXT));
                    ui.label(RichText::new("(newest first)").size(11.0).color(MUTED));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Clear").clicked() {
                            self.logs.clear();
                        }
                    });
                });
                ui.add_space(4.0);
                // Newest entry first, so the latest is always pinned at the top
                // (fully visible, no scrolling/clipping). Scroll down for history.
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if self.logs.is_empty() {
                            ui.label(RichText::new("No activity yet.").italics().color(MUTED));
                        }
                        for line in self.logs.iter().rev() {
                            ui.label(RichText::new(line).monospace().size(12.0).color(TEXT));
                        }
                    });
            });

        // Fixed top + tabbed tool area.
        egui::CentralPanel::default().show_inside(ui, |ui| {
            self.header(ui);
            ui.add_space(10.0);
            self.banner(ui);
            ui.add_space(10.0);
            self.system_card(ui);
            ui.add_space(12.0);
            self.action_buttons(ui);
            ui.add_space(10.0);
            self.tab_bar(ui);
            ui.add_space(8.0);
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    card(ui, |ui| match self.active_tab {
                        Tab::Exclusions => self.tab_exclusions(ui),
                        Tab::OtherAv => self.tab_other_av(ui),
                        Tab::Firewall => self.tab_firewall(ui),
                        Tab::Advanced => self.tab_advanced(ui),
                    });
                });
        });
    }
}

impl DefenderControlApp {
    fn header(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if let Some(tex) = &self.logo {
                ui.add(egui::Image::new(egui::load::SizedTexture::new(
                    tex.id(),
                    egui::vec2(48.0, 48.0),
                )));
                ui.add_space(4.0);
            }
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Defender Control").size(23.0).strong().color(TEXT));
                    ui.label(RichText::new(version_label()).size(14.0).color(ACCENT));
                });
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    ui.hyperlink_to(
                        RichText::new("robloxscripts.com").size(12.0),
                        "https://robloxscripts.com",
                    )
                    .on_hover_text("The best place to get and share Roblox scripts.");
                    ui.label(RichText::new("&").size(12.0).color(MUTED));
                    ui.hyperlink_to(
                        RichText::new("rsware.store").size(12.0),
                        "https://rsware.store",
                    )
                    .on_hover_text("The best place to buy Roblox executors & externals.");
                });
            });
        });
    }

    fn banner(&mut self, ui: &mut egui::Ui) {
        let (bg, label) = if self.disabled {
            (BANNER_RED, "Windows Defender is DISABLED")
        } else {
            (BANNER_GREEN, "Windows Defender is ENABLED")
        };
        egui::Frame::NONE
            .fill(bg)
            .corner_radius(egui::CornerRadius::same(10))
            .inner_margin(egui::Margin::same(13))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    status_dot(ui, Color32::WHITE);
                    ui.add_space(2.0);
                    ui.label(RichText::new(label).size(18.0).strong().color(Color32::WHITE));
                });
            });
        if self.disabled {
            ui.add_space(5.0);
            ui.label(
                RichText::new("Still blocked from using executors or externals? Use the tabs below.")
                    .color(ORANGE)
                    .strong(),
            );
        }
    }

    fn system_card(&mut self, ui: &mut egui::Ui) {
        let compat = self.sys.compatible;
        let mut info = self.sys.os.clone();
        if !self.sys.version.is_empty() {
            info.push_str(&format!("  ·  {}", self.sys.version));
        }
        info.push_str(&format!("  ·  build {}  ·  {}", self.sys.build, self.sys.arch));
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                status_dot(ui, if compat { GREEN } else { RED });
                ui.label(
                    RichText::new(if compat { "Compatible" } else { "Not compatible" })
                        .strong()
                        .color(if compat { GREEN } else { RED }),
                );
                ui.label(RichText::new(info).color(MUTED).size(12.5));
            });
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                status_dot(ui, if self.elevated { GREEN } else { RED });
                ui.label(
                    RichText::new(if self.elevated { "Administrator: yes" } else { "Administrator: no" })
                        .color(TEXT),
                );
                ui.add_space(12.0);
                let (c, t) = match self.tamper {
                    Some(true) => (ORANGE, "Tamper Protection: ON"),
                    Some(false) => (GREEN, "Tamper Protection: off"),
                    None => (MUTED, "Tamper Protection: unknown"),
                };
                status_dot(ui, c);
                ui.label(RichText::new(t).color(TEXT));
            });
            if !self.elevated && ui.small_button("Relaunch as administrator").clicked() {
                relaunch_as_admin();
            }
        });
    }

    fn action_buttons(&mut self, ui: &mut egui::Ui) {
        let bw = (ui.available_width() - 8.0) / 2.0;
        ui.horizontal(|ui| {
            let enable = ui
                .add_enabled(
                    self.disabled,
                    egui::Button::new(
                        RichText::new("Enable Defender").size(15.0).strong().color(Color32::WHITE),
                    )
                    .fill(BTN_GREEN)
                    .min_size(egui::vec2(bw, 42.0)),
                )
                .clicked();
            let disable = ui
                .add_enabled(
                    !self.disabled,
                    egui::Button::new(
                        RichText::new("Disable Defender").size(15.0).strong().color(Color32::WHITE),
                    )
                    .fill(BTN_RED)
                    .min_size(egui::vec2(bw, 42.0)),
                )
                .clicked();
            if enable {
                match enable_defender() {
                    Ok(()) => self.log(
                        "Enabled Defender (removed policy keys). A restart may be needed for Windows Security to fully refresh.",
                    ),
                    Err(e) => self.log(format!("Enable failed: {e}")),
                }
                self.refresh();
            }
            if disable {
                match disable_defender() {
                    Ok(()) => {
                        self.log("Disabled Defender (set policy keys).");
                        if self.tamper == Some(true) {
                            self.log("Note: Tamper Protection is ON — Windows may revert this.");
                        }
                    }
                    Err(e) => self.log(format!("Disable failed: {e}")),
                }
                self.refresh();
            }
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("Refresh status").clicked() {
                self.refresh();
                self.log("Refreshed status.");
            }
            if ui.button("Verify real state (live)").clicked() {
                let ctx = ui.ctx().clone();
                self.spawn_job(&ctx, |tx| {
                    let msg = match defender_live_status() {
                        Ok(s) => format!("Live — {s}"),
                        Err(e) => format!("Live check failed: {e}"),
                    };
                    let _ = tx.send(Job::Log(msg));
                });
            }
        });

        if self.busy.load(Ordering::SeqCst) {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Working…").size(12.0).color(MUTED));
            });
        }

        ui.add_space(6.0);
        let upd = self.update.lock().unwrap().clone();
        ui.horizontal(|ui| match &upd {
            UpdateState::Checking => {
                ui.spinner();
                ui.label(RichText::new("Checking for updates…").size(12.0).color(MUTED));
            }
            UpdateState::UpToDate => {
                ui.label(
                    RichText::new(format!("Up to date  ({})", version_label()))
                        .size(12.0)
                        .color(GREEN),
                );
                if ui.small_button("Check again").clicked() {
                    let ctx = ui.ctx().clone();
                    self.spawn_update_check(&ctx);
                }
            }
            UpdateState::Available { tag, url } => {
                ui.label(RichText::new(format!("Update available: {tag}")).strong().color(ORANGE));
                let clicked = ui
                    .add(
                        egui::Button::new(RichText::new("Update now").strong().color(Color32::WHITE))
                            .fill(BTN_GREEN),
                    )
                    .clicked();
                if clicked {
                    let ctx = ui.ctx().clone();
                    let url = url.clone();
                    self.log(format!("Downloading update {tag}…"));
                    self.start_update(&ctx, url);
                }
                if ui.button("Later").clicked() {
                    *self.update.lock().unwrap() = UpdateState::Dismissed;
                }
            }
            UpdateState::Downloading => {
                ui.spinner();
                ui.label(
                    RichText::new("Downloading update… the app will restart.")
                        .size(12.0)
                        .color(ACCENT),
                );
            }
            UpdateState::Failed(e) => {
                ui.label(RichText::new("Update check unavailable").size(12.0).color(MUTED))
                    .on_hover_text(e.clone());
                if ui.small_button("Retry").clicked() {
                    let ctx = ui.ctx().clone();
                    self.spawn_update_check(&ctx);
                }
            }
            UpdateState::Dismissed => {
                if ui.small_button("Check for updates").clicked() {
                    let ctx = ui.ctx().clone();
                    self.spawn_update_check(&ctx);
                }
            }
        });
    }

    fn tab_bar(&mut self, ui: &mut egui::Ui) {
        ui.columns(4, |cols| {
            let tabs = [
                (Tab::Exclusions, "Exclusions"),
                (Tab::OtherAv, "Other AV"),
                (Tab::Firewall, "Firewall"),
                (Tab::Advanced, "Advanced"),
            ];
            for (i, (tab, label)) in tabs.into_iter().enumerate() {
                let w = cols[i].available_width();
                let selected = self.active_tab == tab;
                if cols[i]
                    .add_sized([w, 30.0], egui::Button::selectable(selected, label))
                    .clicked()
                {
                    self.active_tab = tab;
                }
            }
        });
    }

    fn tab_exclusions(&mut self, ui: &mut egui::Ui) {
        body(
            ui,
            "Safer than disabling: Defender keeps running but ignores the file or folder you add \
             (e.g. your executor's folder).",
        );
        hint(ui, "Requires Tamper Protection OFF. Added paths also appear in Windows Security > Virus & threat protection > Manage settings > Exclusions.");
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Path:").color(TEXT));
            ui.add(
                egui::TextEdit::singleline(&mut self.exclusion_path)
                    .hint_text(r"C:\Executor  or  C:\...\app.exe")
                    .desired_width(220.0),
            );
        });
        ui.horizontal(|ui| {
            if ui.button("Browse file…").clicked()
                && let Some(p) = rfd::FileDialog::new()
                    .set_title("Select a program to exclude")
                    .add_filter("Programs", &["exe"])
                    .pick_file()
                {
                    self.exclusion_path = p.display().to_string();
                }
            if ui.button("Browse folder…").clicked()
                && let Some(p) = rfd::FileDialog::new()
                    .set_title("Select a folder to exclude")
                    .pick_folder()
                {
                    self.exclusion_path = p.display().to_string();
                }
        });
        ui.horizontal(|ui| {
            if ui.button("Add exclusion").clicked() {
                let p = self.exclusion_path.trim().to_string();
                if p.is_empty() {
                    self.log("Enter or browse a path first.");
                } else {
                    let ctx = ui.ctx().clone();
                    self.spawn_job(&ctx, move |tx| match defender_add_exclusion(&p) {
                        Ok(()) => {
                            let _ = tx.send(Job::Log(format!("Added Defender exclusion: {p}")));
                            let _ = tx.send(Job::Exclusions(defender_list_exclusions()));
                        }
                        Err(e) => {
                            let _ = tx.send(Job::Log(format!("Add exclusion failed: {e}")));
                        }
                    });
                }
            }
            if ui.button("Remove exclusion").clicked() {
                let p = self.exclusion_path.trim().to_string();
                if p.is_empty() {
                    self.log("Enter or browse a path first.");
                } else {
                    let ctx = ui.ctx().clone();
                    self.spawn_job(&ctx, move |tx| match defender_remove_exclusion(&p) {
                        Ok(()) => {
                            let _ = tx.send(Job::Log(format!("Removed Defender exclusion: {p}")));
                            let _ = tx.send(Job::Exclusions(defender_list_exclusions()));
                        }
                        Err(e) => {
                            let _ = tx.send(Job::Log(format!("Remove exclusion failed: {e}")));
                        }
                    });
                }
            }
            if ui.button("Refresh list").clicked() {
                let ctx = ui.ctx().clone();
                self.spawn_job(&ctx, |tx| {
                    let list = defender_list_exclusions();
                    let _ = tx.send(Job::Log(format!("Loaded {} Defender exclusion(s).", list.len())));
                    let _ = tx.send(Job::Exclusions(list));
                });
            }
        });
        if self.exclusions_loaded {
            ui.add_space(4.0);
            if self.exclusions.is_empty() {
                hint(ui, "No path exclusions set.");
            } else {
                ui.label(RichText::new("Current exclusions:").strong().color(TEXT));
                let current = self.exclusions.clone();
                for ex in &current {
                    ui.horizontal(|ui| {
                        if ui.small_button("Remove").clicked() {
                            let ctx = ui.ctx().clone();
                            let ex = ex.clone();
                            self.spawn_job(&ctx, move |tx| match defender_remove_exclusion(&ex) {
                                Ok(()) => {
                                    let _ = tx.send(Job::Log(format!("Removed exclusion: {ex}")));
                                    let _ = tx.send(Job::Exclusions(defender_list_exclusions()));
                                }
                                Err(e) => {
                                    let _ = tx.send(Job::Log(format!("Remove failed: {e}")));
                                }
                            });
                        }
                        ui.label(RichText::new(ex).color(TEXT));
                    });
                }
            }
        }
    }

    fn tab_other_av(&mut self, ui: &mut egui::Ui) {
        if ui.button("Check for other antivirus programs").clicked() {
            self.av_results = scan_installed_av();
            self.av_scanned = true;
            self.pending_uninstall = None;
            self.log(format!(
                "Scanned installed programs: {} antivirus product(s) found.",
                self.av_results.len()
            ));
        }
        if self.av_scanned {
            if self.av_results.is_empty() {
                ui.horizontal(|ui| {
                    status_dot(ui, GREEN);
                    ui.label(RichText::new("No third-party antivirus detected.").color(GREEN));
                });
            } else {
                ui.horizontal(|ui| {
                    status_dot(ui, ORANGE);
                    ui.label(
                        RichText::new(format!(
                            "{} third-party antivirus product(s) detected:",
                            self.av_results.len()
                        ))
                        .strong()
                        .color(ORANGE),
                    );
                });
                let results = self.av_results.clone();
                for av in &results {
                    ui.horizontal(|ui| {
                        if av.uninstall.is_some() && ui.small_button("Uninstall…").clicked() {
                            self.pending_uninstall = Some(av.clone());
                        }
                        ui.label(RichText::new(&av.name).color(TEXT));
                    });
                }
                ui.add_space(8.0);
                ui.label(
                    RichText::new("To allow your program without uninstalling:")
                        .strong()
                        .color(TEXT),
                );
                step(ui, 1, "Open that antivirus' dashboard.");
                step(ui, 2, "Find Settings > Exclusions / Allowed apps / Whitelist.");
                step(ui, 3, "Add BOTH your program's .exe and its whole folder.");
                step(ui, 4, "If it has a 'ransomware' or 'folder protection' list, add it there too.");
                hint(ui, "Wording varies (Avast: Settings > Exceptions; Norton: Settings > Antivirus > Exclusions).");
            }
        }
        if let Some(av) = self.pending_uninstall.clone() {
            ui.add_space(6.0);
            ui.group(|ui| {
                ui.label(
                    RichText::new(format!("Run the uninstaller for \"{}\"?", av.name))
                        .strong()
                        .color(ORANGE),
                );
                if av.interactive {
                    hint(ui, "Its own uninstall wizard will open.");
                }
                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new(RichText::new("Yes, uninstall").color(Color32::WHITE)).fill(BTN_RED))
                        .clicked()
                    {
                        if let Some(cmd) = &av.uninstall {
                            match run_uninstall_string(cmd) {
                                Ok(()) => self.log(format!("Launched uninstaller for {}.", av.name)),
                                Err(e) => self.log(format!("Could not start uninstaller for {}: {e}", av.name)),
                            }
                        }
                        self.pending_uninstall = None;
                    }
                    if ui.button("Cancel").clicked() {
                        self.pending_uninstall = None;
                    }
                });
            });
        }
    }

    fn tab_firewall(&mut self, ui: &mut egui::Ui) {
        body(
            ui,
            "If your executor / external still won't connect after disabling Defender and removing \
             other antivirus, Windows Firewall may be blocking it.",
        );
        ui.add_space(4.0);
        ui.label(RichText::new("Allow it manually:").strong().color(TEXT));
        step(ui, 1, "Windows Security > Firewall & network protection > Allow an app through firewall.");
        step(ui, 2, "Change settings > Allow another app… > Browse to the .exe > Add.");
        step(ui, 3, "Tick both Private and Public.");
        ui.add_space(6.0);
        ui.label(RichText::new("…or let this app add the rules for you:").strong().color(TEXT));
        ui.horizontal(|ui| {
            ui.label(RichText::new("Program:").color(TEXT));
            ui.add(
                egui::TextEdit::singleline(&mut self.firewall_exe_path)
                    .hint_text(r"C:\path\to\program.exe")
                    .desired_width(190.0),
            );
            if ui.button("Browse…").clicked()
                && let Some(p) = rfd::FileDialog::new()
                    .set_title("Select the program to allow")
                    .add_filter("Programs", &["exe"])
                    .pick_file()
                {
                    self.firewall_exe_path = p.display().to_string();
                }
        });
        ui.horizontal(|ui| {
            if ui.button("Allow through firewall").clicked() {
                let p = self.firewall_exe_path.trim().to_string();
                if p.is_empty() {
                    self.log("Choose the .exe first.");
                } else {
                    match add_firewall_rules(Path::new(&p)) {
                        Ok(()) => self.log(format!("Added inbound + outbound firewall allow rules for {p}.")),
                        Err(e) => self.log(format!("Firewall rule failed: {e}")),
                    }
                }
            }
            if ui.button("Open Firewall settings").clicked() {
                let _ = Command::new("control").arg("firewall.cpl").spawn();
            }
        });
        ui.add_space(10.0);
        ui.label(
            RichText::new("Still won't connect? A free VPN can bypass network/ISP blocks:")
                .strong()
                .color(TEXT),
        );
        ui.horizontal(|ui| {
            ui.label(RichText::new("•").color(ACCENT));
            ui.hyperlink_to("Proton VPN (free)", "https://protonvpn.com/free-vpn");
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new("•").color(ACCENT));
            ui.hyperlink_to("Cloudflare WARP (1.1.1.1)", "https://one.one.one.one/");
        });
    }

    fn tab_advanced(&mut self, ui: &mut egui::Ui) {
        body(
            ui,
            "Goes beyond the policy keys: also flips Defender's live settings (real-time, behavior, \
             IOAV, script and archive scanning) and tries to stop/disable the WinDefend + WdNisSvc \
             services.",
        );
        hint(
            ui,
            "Most of this only works with Tamper Protection OFF, and Windows often refuses to stop \
             the protected WinDefend service even then. Every step's real result is shown in the log.",
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui
                .add(
                    egui::Button::new(RichText::new("Apply aggressive disable").strong().color(Color32::WHITE))
                        .fill(BTN_RED)
                        .min_size(egui::vec2(0.0, 34.0)),
                )
                .clicked()
            {
                let ctx = ui.ctx().clone();
                self.spawn_job(&ctx, |tx| {
                    let _ = tx.send(Job::Log("--- Aggressive disable ---".to_owned()));
                    for line in aggressive_disable() {
                        let _ = tx.send(Job::Log(line));
                    }
                    let _ = tx.send(Job::Refresh);
                });
            }
            if ui
                .add(
                    egui::Button::new(RichText::new("Re-enable everything").strong().color(Color32::WHITE))
                        .fill(BTN_GREEN)
                        .min_size(egui::vec2(0.0, 34.0)),
                )
                .clicked()
            {
                let ctx = ui.ctx().clone();
                self.spawn_job(&ctx, |tx| {
                    let _ = tx.send(Job::Log("--- Full re-enable ---".to_owned()));
                    for line in full_reenable() {
                        let _ = tx.send(Job::Log(line));
                    }
                    let _ = tx.send(Job::Refresh);
                });
            }
        });
    }
}

/// Largest window client height that fits above the taskbar (so the bottom
/// activity log is never pushed off-screen on smaller displays).
fn max_inner_height() -> f32 {
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CYFULLSCREEN};
    let h = unsafe { GetSystemMetrics(SM_CYFULLSCREEN) };
    if h > 300 { h as f32 } else { 720.0 }
}

fn main() -> eframe::Result {
    let height = 720.0_f32.min(max_inner_height());
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([520.0, height])
        .with_resizable(false);
    if let Ok(icon) = eframe::icon_data::from_png_bytes(LOGO_PNG) {
        viewport = viewport.with_icon(Arc::new(icon));
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    let title = format!("Defender Control {}", version_label());
    eframe::run_native(
        &title,
        options,
        Box::new(|cc| {
            setup_style(&cc.egui_ctx);
            let app = DefenderControlApp {
                logo: load_logo(&cc.egui_ctx),
                ..Default::default()
            };
            app.spawn_update_check(&cc.egui_ctx);
            Ok(Box::new(app))
        }),
    )
}

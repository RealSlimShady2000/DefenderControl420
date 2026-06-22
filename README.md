# Defender Control 420

A small, modern Windows GUI to toggle Windows Defender, whitelist your apps,
clear out other antivirus, and unblock programs through the firewall — built for
getting Roblox executors / externals running without the usual headaches.

**Fully vibe coded by [robloxscripts.com](https://robloxscripts.com) &
[rsware.store](https://rsware.store).**

- **[robloxscripts.com](https://robloxscripts.com)** — the best place to get and share Roblox scripts.
- **[rsware.store](https://rsware.store)** — the best place to buy Roblox executors & externals.

Works on **Windows 10 and Windows 11** (64-bit). Single self-contained `.exe` —
nothing to install (the C runtime is statically linked, so there's no Visual C++
Redistributable to chase down).

## Download

Grab the latest **`DefenderControl420.exe`** from the
[**Releases**](https://github.com/RealSlimShady2000/DefenderControl420/releases/latest)
page, then double-click it (it asks for administrator rights automatically).

The app also **checks for updates on launch** and offers to update itself in
place when a newer release is published — no re-downloading by hand.

## Features

- **Enable / Disable Defender** — flips the Group Policy + real-time-protection
  registry values. A **"Verify real state (live)"** button confirms the actual
  status via `Get-MpComputerStatus`.
- **Defender exclusions** — keep Defender on but whitelist a file/folder (e.g.
  your executor's folder). Safer than fully disabling.
- **Other antivirus** — scans installed programs for ~50 known AV products and
  offers to uninstall them or shows how to add exclusions.
- **Firewall & VPN** — add inbound/outbound allow rules for a program, or open
  the Firewall UI; plus free-VPN pointers if a network block remains.
- **Advanced** — aggressive disable via `Set-MpPreference` + the `WinDefend`
  service (honest about what Windows allows).
- **Auto-update** — checks this repo's releases and self-installs newer builds.

## Requirements

These aren't installable packages — the app detects and guides you:

1. **Administrator** — triggered automatically via UAC on launch.
2. **Tamper Protection OFF** — when it's on, Windows reverts any change. Turn it
   off once in *Windows Security → Virus & threat protection → Manage settings →
   Tamper Protection*. The app shows the current state up top.

> Note: on Windows 10 22H2, Microsoft ignores the old policy that used to *lock*
> the Virus & threat protection page, so that page may still open even when
> protection is actually off. Use **Verify real state (live)** to confirm.

## Build from source

Requires the Rust toolchain (MSVC target) on Windows:

```sh
cargo build --release
```

Output: `target\release\defender-control.exe` — a single self-contained file.
`package.ps1` builds it and drops a portable copy on your Desktop.

## Disclaimer

This is a tool for managing **your own machine**. Disabling antivirus lowers
your protection — use it deliberately and re-enable when you're done. Provided
as-is, no warranty.

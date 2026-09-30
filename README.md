# SecuredStorage

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey.svg)](https://github.com/rituparnaprof/securedstorage)
[![Framework](https://img.shields.io/badge/Framework-Tauri%20v2%20%2B%20Rust-orange.svg)](https://tauri.app/)
[![Build Multi-Platform Binaries](https://github.com/rituparnaprof/securedstorage/actions/workflows/build.yml/badge.svg)](https://github.com/rituparnaprof/securedstorage/actions/workflows/build.yml)

**SecuredStorage** is an offline, zero-cloud, post-quantum compliant password vault built with **Tauri v2** and **Rust**, engineered to protect sensitive credentials through hardware-level memory scrubbing, operating system biometrics, and anti-surveillance window shielding.

---

## What it does

- **True Zero-Cloud Offline Security**: Stores all credentials locally on your physical device encrypted with AES-256-GCM. No servers, no accounts, no telemetry, and zero network sockets compiled into the binary.
- **Hardware Biometrics + PIN Unlock**: Unlock seamlessly with Touch ID on macOS or Windows Hello, authenticated by an enclave-derived hardware token and a mandatory 6-digit numeric PIN.
- **Master Password-Gated Edit & Delete**: Editing and permanently deleting credentials strictly require Master Password re-authentication, preventing accidental changes or unauthorized tampering while the vault is open.
- **Ephemeral 10-Second Reveal**: Only the Site name is shown by default. Usernames, passwords, and notes remain masked (`••••••••••••`) until individually revealed, automatically re-masking after 10 seconds.
- **Anti-Screenshot & Screen-Recording Blackout**: Protects against malware, remote desktop sessions, OBS/Zoom screenshares, and OS screenshot tools by rendering the window black to capture APIs.
- **Anti-Copy & Clipboard Lockdown**: Suppresses copy/cut shortcuts, context menus, and text selection, ensuring credentials can never be intercepted by clipboard loggers.
- **Power-Loss Resilient Atomic Storage**: Writes data via write-sync-rename (`vault.enc.tmp` ➔ `fsync` ➔ atomic rename) backed by automated rolling backup snapshots (`.bak`).
- **Emergency Paper Recovery Key**: Generates a 32-character paper recovery code during initial setup to safely restore your vault if you ever lose your Master Password.

For technical details, component breakdown, cryptographic specifications, and threat models, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Requirements

- **Operating System**:
  - macOS 11.0 (Big Sur) or later (Apple Silicon & Intel)
  - Windows 10 / 11 (64-bit)
  - Linux (Ubuntu 22.04+, Debian, Fedora, Arch)
- **Toolchain (Source Build)**: Rust 1.75+ and Node.js 18+

---

## Installation & Getting Started

### Option 1: Download Pre-Built Binaries

1. Download the package for your operating system from the [Releases](https://github.com/rituparnaprof/securedstorage/releases) page:
   - **macOS**: `SecuredStorage-macOS.zip`
   - **Windows**: `SecuredStorage_1.2.0_x64-setup.exe` or standalone portable executable
   - **Linux**: `secured-storage_1.2.0_amd64.deb` or `.AppImage`
2. Extract or run the installer for your platform.
3. **Bypassing macOS Gatekeeper (`xattr`)**:
   > [!NOTE]
   > Because this is a free, independent open-source project without a paid Apple Developer subscription, the binary is not notarized by Apple. macOS Gatekeeper may flag downloaded binaries with *"cannot be opened because the developer cannot be verified"* or *"is damaged"*.
   >
   > To clear the macOS quarantine attribute, open **Terminal** and run:
   > ```bash
   > xattr -cr /Applications/SecuredStorage.app
   > ```
   > *(Alternatively: Right-click / Control-click `SecuredStorage.app` in Finder, select **Open**, and click **Open** in the confirmation dialog).*

---

### Option 2: Build & Run Locally from Source

Building the application on your own machine creates an ad-hoc signed local binary:

1. **Install Prerequisites**:
   - Install **Rust**:
     ```bash
     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
     ```
   - Install **Node.js** (v18+).

2. **Clone the Repository**:
   ```bash
   git clone https://github.com/rituparnaprof/securedstorage.git
   cd securedstorage
   ```

3. **Install Dependencies**:
   ```bash
   npm install
   ```

4. **Run in Development Mode**:
   ```bash
   npm run tauri dev
   ```

5. **Compile an Optimized Release Binary**:
   ```bash
   npm run tauri build
   ```
   The compiled native binary will be generated under `src-tauri/target/release/bundle/`.

---

## Important Warnings & Disclaimers

### 1. Zero-Cloud & Master Password Loss Warning
> [!CAUTION]
> SecuredStorage has **no central servers, no cloud sync, and no password reset mechanisms**.
> 
> All credentials are mathematically encrypted using **AES-256-GCM** with keys derived from your **Master Password** and **Emergency Paper Recovery Key**. If you lose both your Master Password and your Paper Recovery Key, **your data is cryptographically unrecoverable**. Always store your Emergency Paper Recovery Key in a safe physical location.

### 2. AI / LLM Implementation Notice
> [!NOTE]
> Most of the code in this repository was generated with the assistance of Large Language Models (LLMs). The core concept, system architecture, functional specifications, and validation were designed and directed by the author.

### 3. Trademark Disclaimer
> [!IMPORTANT]
> macOS, Apple, and Touch ID are trademarks of Apple Inc. Windows and Windows Hello are trademarks of Microsoft Corporation. Linux is a registered trademark of Linus Torvalds. Ubuntu is a registered trademark of Canonical Ltd. Debian, Fedora, Arch Linux, and other referenced trademarks, product names, and logos belong to their respective owners.
>
> **SecuredStorage** is an independent open-source project and is not affiliated with, endorsed by, sponsored by, or associated with any of these trademark holders. All operating system and distribution names are used strictly for compatibility identification purposes.
>
> UI icons are provided by [Lucide](https://lucide.dev) / [Feather](https://feathericons.com) under the MIT/ISC licenses.

---

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0-or-later)**. See the [LICENSE](LICENSE) file for the full license text.

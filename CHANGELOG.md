# Changelog

All notable changes to the **SecuredStorage** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Hardware security key (YubiKey / FIDO2 CTAP2) fallback token integration.
- Encrypted cross-device backup QR pairing protocol (zero-cloud).

## [1.0.10] - 2026-09-26

### Added
- **Automated Biometric Trigger & Instant PIN Focus Flow**:
  - The application now triggers the native biometric prompt (Touch ID on macOS, Windows Hello on Windows, PAM on Linux) automatically upon showing the lock/auth screen, removing the need for manual button clicks.
  - As soon as the biometric sensor confirms authentication, the UI transitions to Step 2 and immediately autofocused the 6-digit numeric PIN field.
  - Automatically submits decryption as soon as the 6th digit of the PIN is entered.
- **WCAG AAA Light Mode Contrast & Theming**:
  - Added dedicated high-contrast CSS design tokens (`--bg-warning`, `--border-warning`, `--text-warning`, `--bg-recovery`, `--border-recovery`, `--text-recovery`) for Light, Dark, Tint, and Glass modes.
  - Light mode displays sharp, high-contrast dark amber text (`#78350f` on `#fef3c7` and `#fffbeb`), eliminating illegibility in bright environments.
- **Streamlined "Site" Credential Schema**:
  - Completely removed the redundant `Application` field from the "Add Credential" modal and vault entries table.
  - Renamed `Website` to **`Site`** with clear plain-text guidance (e.g., Google, Banking, AWS, Work Email) rather than requiring full URL syntax.
  - Adjusted vault table column widths to 5 cleanly aligned columns (`Site`, `Username`, `Password`, `Notes`, `Actions`).

## [1.0.9] - 2026-09-26

### Added
- **Native macOS Touch ID Integration (`LocalAuthentication`)**:
  - Bridged native Objective-C `LAContext` (`src/touchid_macos.m`) directly into the Rust core to trigger the system Touch ID biometric sensor prompt.
  - Implemented a two-step authentication UX: users scan Touch ID first, and once biometric authentication is verified, the UI reveals the 6-digit PIN input to decrypt the vault.
- **Emergency Paper Recovery Key (Slot 3)**:
  - Added a third cryptographic key slot wrapping the Master Encryption Key (MEK) with a high-entropy 128-bit air-gapped paper recovery code (`SEC-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`).
  - Added a dedicated "Emergency Recovery" tab on the authentication screen allowing users to restore their vault and reset their Master Password and PIN even if credentials are forgotten.
  - Implemented automatic recovery key rotation upon each successful recovery.

---

## [1.0.8] - 2026-09-26

### Added
- **Native Test Suite & Local Compilation Verification**:
  - Implemented unit tests in [`src/crypto.rs`](file:///Users/rituparna/Documents/code/SecuredStorage/src-tauri/src/crypto.rs) covering MEK generation, AES-256-GCM roundtrip, dual-slot key derivation lifecycle, and constant-time comparison.
  - Implemented unit tests in [`src/vault.rs`](file:///Users/rituparna/Documents/code/SecuredStorage/src-tauri/src/vault.rs) covering default masked view enforcement, credential payload encryption/decryption, and session zeroization.
  - Successfully verified end-to-end compilation with `cargo check`, `cargo test` (all 7 tests passed), and local macOS bundle compilation (`SecuredStorage.app`).

---

## [1.0.7] - 2026-09-26

### Added
- **GNU General Public License v3.0 (GPL-3.0-or-later)**:
  - Added official GNU GPL 3.0 [`LICENSE`](file:///Users/rituparna/Documents/code/SecuredStorage/LICENSE) file to project root.
  - Formally licensed repository in `Cargo.toml` and `package.json` (`license = "GPL-3.0-or-later"`).
  - Embedded standard GNU GPL-3.0 copyright header across all source files: Rust backend (`main.rs`, `lib.rs`, `crypto.rs`, `security.rs`, `vault.rs`, `build.rs`), client frontend (`app.js`, `style.css`, `index.html`), and project documentation (`README.md`).

---

## [1.0.6] - 2026-09-26

### Added
- **Automated GitHub Release & Tag Publishing**:
  - Integrated `softprops/action-gh-release@v2` into `.github/workflows/build.yml`.
  - Pushing any git tag starting with `v*` (e.g., `v1.0.0`) automatically creates an official GitHub Release, publishing all standalone binaries, `.dmg`, `.exe`, `.msi`, `.AppImage`, and `.deb` packages as downloadable release assets.

---

## [1.0.5] - 2026-09-26

### Upgraded
- **Dependencies Audit & Modernization**:
  - Added `package.json` locking official `@tauri-apps/api@^2.1.1` and `@tauri-apps/cli@^2.1.0`.
  - Configured CI compiler to use `@tauri-apps/cli@latest` to always build against the latest stable Tauri runtime.
  - Enhanced JavaScript IPC bridge to support all current and future Tauri v2 invocations (`window.__TAURI__.core.invoke`).

---

## [1.0.4] - 2026-09-26

### Optimized
- **CI/CD Build Speed Optimization**:
  - Integrated `swatinem/rust-cache@v2` across GitHub Actions matrix runners to cache compiled dependencies and crates.
  - Replaced source-compilation of `tauri-cli` (which took 15–20 minutes) with precompiled native binary `@tauri-apps/cli` (taking under 5 seconds).
  - Reduced total CI build times from ~54 minutes down to ~3–5 minutes.

---

## [1.0.3] - 2026-09-26

### Added
- **One-Click Light / Dark Mode Toggle**:
  - Added dedicated header toggle button switching instantly between high-contrast daylight (Light) and deep midnight (Dark) modes.
  - Automatic detection and synchronization with system OS preference (`prefers-color-scheme`).
  - Persistent user preference saved in local storage.

---

## [1.0.2] - 2026-09-26

### Added
- **Adaptive Cross-Platform Iconography**:
  - High-resolution squircle icons with frosted glassmorphic gradients and golden padlock emblem.
  - Multi-resolution support engineered to adapt seamlessly across macOS, Windows, and Linux under Dark, Light, Tint, and Glass theme environments.
  - Formats: Embedded multi-size `.ico` (16, 32, 64, 128, 256), macOS `.icns`, and high-res PNGs up to 512x512.
- **Windows Standalone Portable Executable**:
  - Automated extraction and packaging of `SecuredStorage-Windows-Portable.exe` in GitHub Actions for direct execution without an installer.
- **Centralized CSS Design System**:
  - Unified `style.css` architecture where 100% of component styles inherit from centralized CSS custom properties (`:root` design tokens).
  - Built-in theme switcher supporting Dark, Light, Tint (emerald/cyan), and Glass (translucent acrylic with backdrop blur) schemes.
  - Automatic OS color scheme preference detection.

---

## [1.0.1] - 2026-09-26

### Fixed
- **Windows Build**: Generated `icons/icon.ico` required for Windows resource compiler (`rc.exe`) during Tauri binary generation.
- **macOS Bundler**: Removed built-in system framework `LocalAuthentication` from `bundle.macOS.frameworks` array (system frameworks are dynamically linked by the kernel, not bundled as third-party files).
- **macOS Icons**: Generated Apple standard multi-resolution `icons/icon.icns` bundle.
- **Compiler Warnings**: Cleaned up unused imports and target guards across `src/crypto.rs`, `src/security.rs`, `src/lib.rs`, and `src/vault.rs`.
- **CI Artifact Upload**: Added paths for `.app` and `.rpm` bundles in GitHub Actions workflow.

---

## [1.0.0] - 2026-09-26

### Added
- **Core Cryptographic Engine**:
  - Symmetric data encryption via **AES-256-GCM** (SP 800-38D) providing $2^{128}$ quantum resistance under Grover's algorithm.
  - Memory-hard Key Derivation Function via **Argon2id** ($m=64\text{MB}, t=3, p=4$) preventing quantum/ASIC/GPU brute-force acceleration.
  - Dual-slot key architecture supporting **Master Password** and **Biometrics + 6-Digit PIN**.
  - Post-Quantum Cryptography (PQC) integration architecture aligned with **NIST FIPS 203 (ML-KEM-1024 / Kyber-1024)**.
- **Hardware-Bound Biometric Authentication**:
  - Support for Apple Touch ID (`LocalAuthentication`), Windows Hello (`UserConsentVerifier`), and Linux PAM (`fprintd`).
  - Mandatory **6-digit numeric PIN (`000000`–`999999`)** combined with hardware Secure Enclave / TPM token.
  - In-memory 3-attempt PIN lockout protection falling back to Master Password.
- **Anti-Exfiltration & Copy Protection**:
  - Global blocking of clipboard copying, cutting, context menu, and keyboard shortcuts (`Ctrl+C`, `Cmd+C`, `Ctrl+X`, `Cmd+X`, `Ctrl+A`, `Cmd+A`).
  - Strict CSS enforcement disabling user text selection (`user-select: none`).
- **OS-Level Anti-Screenshot & Screen Capture Protection**:
  - macOS window sharing blackout policy (`NSWindow.sharingType = .none`).
  - Windows display affinity exclusion (`SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`).
  - Window blur detection with immediate auto-lock.
- **In-Memory Security & Anti-Scraping**:
  - Ephemeral "Just-In-Time" decryption: only the requested field is decrypted into RAM for 10 seconds.
  - Automatic memory zeroization (`ZeroizeOnDrop` / `memset_s` / `SecureZeroMemory`) upon re-masking.
  - Physical memory locking (`libc::mlock` / `VirtualLock`) preventing secrets from leaking to OS swap/pagefile.
  - Kernel anti-debugging enforcement via `ptrace(PT_DENY_ATTACH)` on macOS and process DACL restrictions on Windows.
- **User Interface**:
  - Sandboxed Webview UI with strict Content Security Policy (`default-src 'none'`).
  - Default locked-down view: **ONLY `Website` details are visible**; `Application`, `Username`, `Password`, and `Notes` are strictly masked (`••••••••••••`).
  - Modal for credential creation with cryptographically secure random password generator.
  - Inactivity auto-lock timer (2 minutes).
- **CI/CD & Cloud Build**:
  - GitHub Actions multi-platform workflow (`.github/workflows/build.yml`) compiling native packages for Windows (`.exe`, `.msi`), macOS (`.dmg`, `.app`), and Linux (`.AppImage`, `.deb`).

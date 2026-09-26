# Changelog

All notable changes to the **SecuredStorage** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Hardware security key (YubiKey / FIDO2 CTAP2) fallback token integration.
- Encrypted cross-device backup QR pairing protocol (zero-cloud).

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

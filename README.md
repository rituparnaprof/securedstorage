# SecuredStorage: Cross-Platform PQC-Compliant Offline Password Vault
**Supported Platforms: Windows, macOS, Linux**  
**Core Framework: Tauri v2 (Rust Native Core + Sandboxed Webview)**

---

## 1. System Architecture

SecuredStorage is designed as an **offline, zero-cloud, cross-platform native application** using **Tauri v2**. The application combines a modern Web UI with a compiled, memory-safe **Rust** core. 

Unlike purely browser-based solutions:
- **No loose HTML/JS files**: Web assets are embedded directly into the compiled native binary (`.exe` on Windows, `.app` on macOS, binary on Linux).
- **All cryptography runs in compiled Rust**: JavaScript never handles Master Keys, derivation functions, or raw cipher operations.
- **Hardware-bound biometrics**: Direct integration with OS biometric subsystems (Windows Hello, macOS Touch ID, Linux PAM/fprintd).

```
+========================================================================================+
|                               TAURI NATIVE COMPILED BINARY                              |
|                                                                                        |
|  +----------------------------------------------------------------------------------+  |
|  |                   HARDENED WEBVIEW LAYER (Edge WebView2 / WebKit)                |  |
|  |  - Zero Remote CDNs, Zero External Sockets, Strict CSP ('default-src none')      |  |
|  |  - Anti-Copy Enforced: user-select: none, Ctrl+C/Cmd+C/Cut/Context-Menu blocked  |  |
|  |  - Default Vault View: ONLY 'Website' is visible; all other fields MASKED (••••)  |  |
|  |  - Manual Ephemeral Unmask: Single field revealed only upon explicit click        |  |
|  |  - Auto-Lock on user inactivity, window minimize, or window blur                 |  |
|  +------------------------------------------+---------------------------------------+  |
|                                             | Strict Tauri v2 IPC Bridge               |
|                                             | (Strongly Typed Rust Commands)           |
|                                             v                                          |
|  +----------------------------------------------------------------------------------+  |
|  |                             RUST NATIVE SECURITY CORE                            |  |
|  |  - Anti-Screenshot & Screen-Recording Block:                                     |  |
|  |      * macOS: NSWindow.sharingType = .none (Blackout in captures / screen share) |  |
|  |      * Windows: SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) (Blackout)      |  |
|  |      * Linux: Canvas obfuscation on focus loss / Wayland protection              |  |
|  |  - Cryptographic Engine: AES-256-GCM, Argon2id, NIST FIPS 203 (ML-KEM-1024)      |  |
|  |  - Key Management: Master Encryption Key (MEK) locked via `mlock` / `VirtualLock`|  |
|  |  - Automatic Zeroization: `zeroize` crate on all sensitive memory drops          |  |
|  |  - OS Biometric Interfaces:                                                      |  |
|  |      * macOS: `LocalAuthentication` (Touch ID) + Mandatory 6-Digit PIN           |  |
|  |      * Windows: `UserConsentVerifier` (Hello) + Mandatory 6-Digit PIN            |  |
|  |      * Linux: `libpam` / `fprintd` PolicyKit + Mandatory 6-Digit PIN             |  |
|  |  - Cross-Platform Anti-Debugging & Binary Tamper Resistance                      |  |
|  +------------------------------------------+---------------------------------------+  |
+=============================================|==========================================+
                                              v (Encrypted Binary Stream)
                     +--------------------------------------------------+
                     | LOCAL DISK STORAGE: `vault.enc`                  |
                     | Zero Plaintext Ever Touches the Filesystem       |
                     +--------------------------------------------------+
```

---

## 2. Cross-Platform Threat Modeling: 10 Binary Attack Vectors & Countermeasures

Before writing any code, every possible attack vector against the binary across **Windows**, **macOS**, and **Linux** is cataloged along with its engineered countermeasure.

| # | Attack Vector | OS Targets | Attack Methodology | Engineered Countermeasure Closed Before Compilation |
|---|:---|:---|:---|:---|
| **1** | **Memory Scraping (RAM Dumps)** | Windows, macOS, Linux | Malware or a local user dumps the process memory using `ProcDump`, `MiniDumpWriteDump`, `task_for_pid`, `vmmap`, or `/proc/$PID/mem` to search for Master Passwords or plaintext credentials. | **Cross-Platform Memory Locking & Zeroization**:<br>1. Key material is stored in pinned memory (`libc::mlock` on macOS/Linux, `VirtualLock` on Windows) to prevent swapping to disk.<br>2. All secret buffers implement Rust's `Zeroize` and `ZeroizeOnDrop` traits, which guarantee compiler-enforced zeroing (`memset_s` / `SecureZeroMemory`) upon deallocation.<br>3. Plaintext credentials are **never stored as a full list in RAM**; individual entries are decrypted ephemerally on-demand. |
| **2** | **Dynamic Debugging & Hooking** | Windows, macOS, Linux | Attaching debuggers (`x64dbg`, `WinDbg`, `lldb`, `gdb`, `Frida`) to inspect CPU registers, read memory, or alter instruction pointer execution. | **Kernel-Level Anti-Debugging Checks**:<br>• **macOS**: `ptrace(PT_DENY_ATTACH, 0, 0, 0)` at startup causes immediate kernel SIGSEGV if a debugger is attached.<br>• **Windows**: Combined `IsDebuggerPresent()`, `CheckRemoteDebuggerPresent()`, and `NtSetInformationThread(ThreadHideFromDebugger)`.<br>• **Linux**: `prctl(PR_SET_DUMPABLE, 0)` and parent `TracerPid` inspection in `/proc/self/status`. |
| **3** | **Shared Library / DLL Injection** | Windows, macOS, Linux | Forcing the binary to load malicious `.dll`, `.dylib`, or `.so` files to hook functions (`AppInit_DLLs`, `DYLD_INSERT_LIBRARIES`, `LD_PRELOAD`). | **Binary Restriction Policies**:<br>• **macOS**: Signed with Hardened Runtime (`CS_RESTRICT`), disabling `DYLD_*` environment variable processing.<br>• **Windows**: `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` blocks DLL search-order hijacking; Process Signature Policy limits loading to signed binaries.<br>• **Linux**: Explicit capability stripping and `PR_SET_NO_NEW_PRIVS` prevents `LD_PRELOAD` privilege escalation. |
| **4** | **Binary Patching (NOPing Auth Logic)** | Windows, macOS, Linux | Disassembling the binary in Ghidra/IDA and replacing authentication branch instructions (`jz`/`jnz` to `nop`) to bypass Password or Biometrics. | **Cryptographic Key Derivation Gating**:<br>Authentication is **not a boolean flag** (`if (is_authenticated)`). The authentication inputs (Password or Biometric Secret + PIN) **are mathematically required to derive the decryption key via Argon2id**. If the check is NOPed, the derived key is invalid and AES-256-GCM authentication fails mathematically (tag mismatch). |
| **5** | **Webview DevTools & DOM Extraction** | Windows, macOS, Linux | Opening Developer Tools (`F12`, `Ctrl+Shift+I`, `Cmd+Option+I`, right-click "Inspect") to extract passwords directly from the browser DOM. | **Engine-Level DevTools Deactivation**:<br>1. Tauri configuration sets `devtools: false` for production builds, removing DevTools from the Webview engine.<br>2. Context menu is completely disabled at both the webview and JavaScript levels.<br>3. Inspect shortcut keys are trapped and ignored. |
| **6** | **Core Dumps & Paging File Leakage** | Windows, macOS, Linux | OS virtual memory subsystem writes memory pages containing secrets to `pagefile.sys`, `swapfile.sys`, `/var/vm/sleepimage`, or generates crash dumps. | **Process Paging & Crash Dump Prevention**:<br>• **macOS / Linux**: `setrlimit(RLIMIT_CORE, 0)` disables core dumps entirely.<br>• **Windows**: Core dump handling disabled via `SetErrorMode(SEM_FAILCRITICALERRORS)`; `VirtualLock` keeps sensitive pages in physical RAM. |
| **7** | **IPC Interception & Command Forging** | Windows, macOS, Linux | Injected XSS or third-party web content attempts to forge IPC messages to trigger unauthorized file reads or data exfiltration. | **Strictly Typed IPC & Isolation Pattern**:<br>1. Tauri v2 IPC commands use strict Rust serde deserialization with compile-time type validation.<br>2. Content Security Policy (CSP): `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'none'; frame-src 'none'`.<br>3. No raw filesystem or shell execution APIs are exposed to the frontend. |
| **8** | **Ciphertext Tampering & Bit-Flipping** | Windows, macOS, Linux | Modifying bytes in the stored `vault.enc` file on disk to exploit parser logic or cause controlled bit flips. | **AEAD Authenticated Encryption**:<br>AES-256-GCM computes a 128-bit cryptographic authentication tag covering both ciphertext and header metadata. Any modified bit immediately halts decryption with a generic authentication error. |
| **9** | **Data Exfiltration via Copy / Clipboard** | Windows, macOS, Linux | A user, shoulder-surfer, or background monitor attempts to copy data via `Ctrl+C`, `Cmd+C`, `Ctrl+X`, context-menu "Copy", drag-and-drop, or clipboard logging. | **Total Copy Block & Zero-Clipboard Architecture**:<br>1. Global event listeners intercept and block `copy`, `cut`, and `contextmenu`.<br>2. CSS rules enforce `-webkit-user-select: none; user-select: none;` across all UI elements.<br>3. Shortcuts `Ctrl+C`, `Cmd+C`, `Ctrl+A`, `Cmd+A` are trapped and cancelled.<br>4. No clipboard integration exists; credentials can never be copied to the OS clipboard. |
| **10** | **Screen Capture & Screenshot Snooping** | Windows, macOS, Linux | Malware, remote desktop sessions, screen recorders (OBS, Zoom, Teams), or OS screenshot tools (PrintScreen, Snipping Tool, `Cmd+Shift+4`) capture open credentials. | **OS-Level Window Capture Protection**:<br>• **macOS**: `NSWindow.sharingType = .none` renders the application completely black/invisible in screenshots, screen recordings, AirPlay, and screen sharing.<br>• **Windows**: `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` causes the OS compositor to black-out or exclude the window from all capture APIs.<br>• **Linux**: Wayland private surfaces and canvas blur when the window loses active focus. |
| **11** | **Quantum Cryptanalysis (Harvest Now, Decrypt Later)** | Windows, macOS, Linux | A future cryptanalytically relevant quantum computer (CRQC) attempts to break the saved vault files. | **PQC Suite**:<br>1. **Symmetric**: AES-256-GCM ($2^{128}$ quantum security under Grover's algorithm).<br>2. **KDF**: Argon2id (resistant to quantum/ASIC acceleration).<br>3. **Key Encapsulation**: NIST FIPS 203 (ML-KEM-1024 / Kyber-1024) for recovery key wrapping. |

---

## 2.1 Deep-Dive: RAM Security During Unmasking (In-Memory Defense Architecture)

A critical vulnerability in password managers is **RAM scraping**: if malware with administrator or root privileges resides on the operating system, it can attempt to dump the process's virtual memory while a secret is visible. 

SecuredStorage implements a **5-Layer In-Memory Defense** specifically designed to neutralize RAM scraping attacks:

```
[ User Clicks Reveal ] 
         │
         ▼
[ Layer 1: Just-In-Time Decryption ] ──► Only 1 entry decrypted; vault stays AES-256 encrypted in RAM
         │
         ▼
[ Layer 2: Pinned Physical RAM ]     ──► mlock() / VirtualLock() prevents secrets from touching disk swap
         │
         ▼
[ Layer 3: Kernel Shielding ]        ──► PT_DENY_ATTACH / Process DACL blocks ReadProcessMemory & debuggers
         │
         ▼
[ Layer 4: Ephemeral DOM Display ]   ──► Bypasses V8/WebKit string interning tables; isolated in DOM
         │
         ▼
[ Layer 5: Hardware Zeroization ]    ──► On 10s timeout, ZeroizeOnDrop overwrites RAM with 0x00 (memset_s)
```

### 1. Ephemeral "Just-In-Time" Decryption (Zero Plaintext Vault in RAM)
In standard password managers, unlocking the vault decrypts the entire JSON database into memory at once. In SecuredStorage:
- The entire credential store **remains encrypted with AES-256-GCM in RAM at all times**.
- When you click "Reveal" on a specific entry, the Rust core decrypts **only that single entry's field**.
- At any given millisecond, only one secret is decrypted in volatile memory—never your master database.

### 2. Compiler-Enforced Memory Scrubbing (`ZeroizeOnDrop`)
Standard memory deallocation (`free()` or garbage collection) merely flags bytes as reusable; the secret plaintext remains in physical RAM chips for hours.
- All decrypted secret buffers in SecuredStorage implement Rust's `Zeroize` and `ZeroizeOnDrop` traits.
- The instant the 10-second reveal timer elapses (or the user clicks re-mask), the buffer executes hardware-level memory zeroization (`memset_s` / `SecureZeroMemory`).
- The Rust compiler is strictly forbidden from optimizing away or dead-code-eliminating this zeroing pass (`0x00`).

### 3. Kernel-Level Process Shielding (Anti-Memory Dumping)
- **macOS**: At launch, the native binary calls `ptrace(PT_DENY_ATTACH, 0, 0, 0)`. The macOS kernel forbids all external processes—even processes running under `sudo` / `root`—from calling `task_for_pid`, `mach_vm_read`, or attaching `gcore`/`lldb`. Any such attempt triggers a kernel-level `SIGSEGV` crash.
- **Windows**: The process applies a restrictive **Discretionary Access Control List (DACL)** to its process token, stripping `PROCESS_VM_READ` and `PROCESS_QUERY_INFORMATION`. Tools like `ProcDump` or `ReadProcessMemory` receive `ERROR_ACCESS_DENIED`.
- **Linux**: The binary executes `prctl(PR_SET_DUMPABLE, 0)`, blocking non-root `/proc/[PID]/mem` inspection and core generation.

### 4. Pinned Physical Memory (`mlock` / `VirtualLock`)
Operating systems page out inactive memory to the storage drive (`pagefile.sys` on Windows, `/var/vm/sleepimage` on macOS).
- All secret buffers are pinned in physical RAM using `libc::mlock` (POSIX) and `VirtualLock` (Windows).
- Pinned pages are cryptographically guaranteed never to be swapped or paged to disk.

### 5. Anti-String-Interning / Ephemeral DOM Render
Browser engines (WebKit/Blink) pool and intern JavaScript strings across memory heaps.
- Unmasked fields are injected into isolated text nodes that are destroyed and unreferenced immediately upon re-masking.
- The DOM node is replaced with fixed bullet glyphs (`••••••••••••`), clearing references and triggering memory reclamation.

---

## 3. Cryptographic Specification & Dual-Slot Architecture

### 3.1 Primitives
* **Symmetric Cipher**: AES-256-GCM (NIST SP 800-38D) with 256-bit key, 96-bit unique IV per write, and 128-bit authentication tag.
* **Key Derivation Function (KDF)**: Argon2id (RFC 9106)
  * Memory cost: $64\text{ MB}$ ($65,536\text{ KB}$)
  * Time cost (iterations): $t = 3$
  * Parallelism: $p = 4$ lanes
  * Salt: 16 cryptographically secure random bytes (`ring::rand` / `getrandom`)
* **Post-Quantum Key Encapsulation (PQC)**: NIST FIPS 203 (ML-KEM-1024 / Kyber-1024) for emergency recovery keys.

### 3.2 Key Hierarchy & Mandatory 2-Factor Biometric + 6-Digit PIN Flow

Unlocking via Biometrics is **strictly two-factor**: it always requires **both** a physical biometric verification (Touch ID / Windows Hello / PAM) **AND** a secret **6-digit numeric PIN** (000000–999999).

```
                                  +-----------------------------+
                                  | High-Entropy 256-bit Random |
                                  | Master Encryption Key (MEK) |
                                  +-----------------------------+
                                                 |
                   +-----------------------------+-----------------------------+
                   |                                                           |
                   v                                                           v
       [ Slot 1: Master Password ]                      [ Slot 2: Biometric + Mandatory 6-Digit PIN ]
                   |                                                           |
         Master Password + Salt1                              1. Physical Biometric Scan (Touch ID / Hello)
                   |                                             Releases 256-bit Hardware Enclave Secret
           Argon2id (m=64M, t=3)                                               |
                   |                                          2. User Inputs Secret 6-Digit PIN (000000-999999)
                   v                                                           |
             Slot 1 Key                                  3. Combined: (6-Digit PIN || Enclave Secret) + Salt2
                   |                                                           |
                   v                                                 Argon2id (m=64M, t=3)
      AES-256-GCM Encrypted MEK                                                |
                                                                               v
                                                                           Slot 2 Key
                                                                               |
                                                                               v
                                                                  AES-256-GCM Encrypted MEK
```

#### Cryptographic Security of the 6-Digit Numeric PIN:
A 6-digit numeric PIN provides $1,000,000$ combinations ($10^6$), which is standard for device-grade authentication (e.g., Apple iOS, Windows Hello PIN). In SecuredStorage, this is mathematically secured via a **two-layer defense**:
1. **Offline Attack Impossibility (Hardware Cryptographic Binding)**:
   The 6-digit PIN is never hashed in isolation. It is concatenated with the 256-bit `HardwareEnclaveSecret` stored inside the Apple Secure Enclave / Windows TPM 2.0. If an attacker steals the `vault.enc` file, they cannot test the 1,000,000 PIN combinations because they do not possess the physical machine's 256-bit hardware key.
2. **Online Attack Impossibility (Rate Limiting & Lockout)**:
   - Operating system biometric limits (Apple Touch ID locks after 3 failures; Windows Hello throttles after failed attempts).
   - In-app PIN lockout: After 3 consecutive incorrect PIN entries, Slot 2 is locked and disabled until unlocked via the **Master Password**.

### 3.3 Binary File Layout (`vault.enc`)

```
+-------------------------------------------------------------------------+
| Header Magic: 4 bytes ("PQC1")                                          |
| Version: 2 bytes (0x0001)                                               |
+-------------------------------------------------------------------------+
| Key Slot 1 (Master Password Unlock):                                    |
|   - Salt: 16 bytes                                                      |
|   - Nonce / IV: 12 bytes                                                |
|   - Encrypted MEK: 32 bytes                                             |
|   - Auth Tag: 16 bytes                                                  |
+-------------------------------------------------------------------------+
| Key Slot 2 (Biometrics + PIN Unlock):                                   |
|   - Enabled: 1 byte (0x01 = Active, 0x00 = Disabled)                   |
|   - Salt: 16 bytes                                                      |
|   - Nonce / IV: 12 bytes                                                |
|   - Encrypted MEK: 32 bytes                                             |
|   - Auth Tag: 16 bytes                                                  |
+-------------------------------------------------------------------------+
| Vault Payload:                                                          |
|   - Payload Nonce / IV: 12 bytes                                        |
|   - Ciphertext: N bytes (AES-256-GCM of JSON credential collection)     |
|   - Payload Auth Tag: 16 bytes                                          |
+-------------------------------------------------------------------------+
```

### 3.4 Credential Schema & In-Memory JSON Representation

Within the AES-256-GCM encrypted payload, entries follow this strict schema:

```json
[
  {
    "id": "uuid-v4-string",
    "application": "string (e.g., Desktop Client, Banking, Work Tools)",
    "website": "string (e.g., https://login.example.com)",
    "username": "string (e.g., user@example.com)",
    "password": "string (raw sensitive secret)",
    "notes": "string (additional confidential notes)"
  }
]
```

---

## 4. Cross-Platform Biometric Hardware Integration

| OS | Native Biometric API | Hardware Anchor | Fallback Policy |
|:---|:---|:---|:---|
| **macOS** | `LocalAuthentication` (`LAContext`) | Apple Silicon Secure Enclave / T2 Security Chip | 6-Digit PIN combined with Enclave-derived token |
| **Windows** | `Windows.Security.Credentials.UI.UserConsentVerifier` | TPM 2.0 / Windows Hello Container | 6-Digit PIN combined with DPAPI/TPM-protected credential |
| **Linux** | `libpam` / `fprintd` via D-Bus / PolicyKit | Local Secure Keyring / TPM2 | 6-Digit PIN combined with local secret key |

---

## 5. Coding Standards & Security Guidelines

### 5.1 Rust Backend Standards
1. **Zero External Sockets**: No `reqwest`, `hyper`, or TCP/UDP socket dependencies. The binary has zero network communication capabilities.
2. **Memory Scrubbing**: All sensitive structs (`MasterKey`, `DerivedKey`, `PlaintextCredentials`) must derive `Zeroize` and `ZeroizeOnDrop`.
3. **Constant-Time Verification**: Cryptographic comparisons must use `subtle::ConstantTimeEq` to eliminate timing side-channels.
4. **No Descriptive Error Leakage**: All crypto failures return a generic error: `Err("Authentication failed or corrupted vault")`.
5. **No Release Logging**: Debug logging (`println!`, `dbg!`, `log::debug`) is compiled out in release mode using `cfg(debug_assertions)`.
6. **Window Capture Affinities**: The Rust native window setup immediately applies screenshot blackout policies (`NSWindowSharingNone` on macOS / `SetWindowDisplayAffinity` on Windows).

### 5.2 Webview Frontend Standards
1. **Self-Contained Bundling**: All scripts, stylesheets, and icons are bundled locally. Zero external fonts or CDNs.
2. **Strict Content Security Policy (CSP)**:
   ```html
   <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none';">
   ```
3. **No Dynamic Execution**: `eval()`, `Function()`, and `innerHTML` with untrusted data are strictly forbidden. Use DOM manipulation APIs (`textContent`, `createElement`).
4. **Anti-Copy & Selection Lockdown**:
   - Apply `-webkit-user-select: none; user-select: none;` across all elements.
   - Intercept and suppress `copy`, `cut`, `contextmenu`, and drag-and-drop events.
   - Block keyboard combinations (`Ctrl+C`, `Cmd+C`, `Ctrl+X`, `Cmd+X`, `Ctrl+A`, `Cmd+A`).
5. **Strict Masking by Default**:
   - When the vault is unlocked, **ONLY the `Website` details are visible**.
   - `Application`, `Username`, `Password`, and `Notes` are displayed as `••••••••••••`.
   - To view an entry's hidden details, the user must explicitly click a "Reveal" toggle for that specific entry, which unmasks it momentarily.

---

## 6. Build Hardening Configurations

### 6.1 Rust Compilation Flags (`Cargo.toml`)
```toml
[profile.release]
opt-level = 3          # Maximum compiler optimizations
lto = true             # Link-Time Optimization (inlines functions, strips unused code)
codegen-units = 1      # Single codegen unit for deeper global optimization
panic = "abort"        # Eliminates stack unwinding metadata and symbol names
strip = true           # Strips all debug symbols and function names from the binary
overflow-checks = true # Enforces runtime panic on arithmetic overflow
```

### 6.2 OS Binary Hardening Flags
* **macOS**:
  - Hardened Runtime enabled: `--options runtime`
  - Library validation enforced
  - Code signed with Developer Certificate or ad-hoc local identity
* **Windows**:
  - `/DYNAMICBASE` (ASLR)
  - `/NXCOMPAT` (Data Execution Prevention / DEP)
  - `/HIGHENTROPYVA` (64-bit ASLR)
  - Control Flow Guard (`/guard:cf`)
* **Linux**:
  - Full RELRO (`-Wl,-z,relro,-z,now`)
  - Stack Canary (`-fstack-protector-strong`)
  - Position Independent Executable (`-pie`)

---

## 7. Operational Workflow: Authentication, Default View & Manual Unmasking

```
  +-------------------------------------------------------------------+
  | Step 1: Launch Application                                        |
  |         - Window capture protection turns window black to capture |
  |         - Anti-copy and anti-selection event traps active         |
  |         - Prompt: Touch ID + 6-Digit PIN                          |
  |               OR: Master Password                                 |
  |               OR: Emergency Paper Recovery Key (Slot 3)           |
  +---------------------------------+---------------------------------+
                                    |
                                    v
  +-------------------------------------------------------------------+
  | Step 2: Authentication Verification                               |
  |         - Biometric Flow: First scan Touch ID, then punch PIN     |
  |         - Rust derives key via Argon2id (m=64M, t=3, p=4)         |
  |         - AES-256-GCM decrypts Master Encryption Key (MEK)        |
  +---------------------------------+---------------------------------+
                                    |
                                    v
  +-------------------------------------------------------------------+
  | Step 3: Default Vault View (Locked Down)                          |
  |         - Displays list of stored entries                         |
  |         - ONLY `Website` details are shown in plaintext           |
  |         - `Application`, `Username`, `Password`, `Notes` MASKED   |
  |           (Rendered as bullet dots ••••••••••••)                  |
  +---------------------------------+---------------------------------+
                                    |
            +-----------------------+-----------------------+
            |                                               |
            v                                               v
  +----------------------------------+   +----------------------------------+
  | Step 4A: Manual Unmask           |   | Step 4B: Add / Edit Credential   |
  | - User clicks explicit eye icon  |   | - Click "Add Entry" modal        |
  | - Specific field unmasks in DOM  |   | - Enter Application, Website,    |
  | - Auto-remasks after 10 seconds  |   |   Username, Password, Notes      |
  | - Copying remains blocked        |   | - Rust core commits and encrypts |
  +----------------------------------+   +----------------------------------+
                                    |
                                    v
  +-------------------------------------------------------------------+
  | Step 5: Auto-Lock on Inactivity or Window Blur                    |
  |         - 2 minutes of idle time or minimizing/blurring window    |
  |         - Zeroizes MEK in RAM, purges DOM, returns to Step 1      |
  +-------------------------------------------------------------------+
```

---

## License

This project is licensed under the **GNU General Public License v3.0** (GPL-3.0-or-later).

See the [LICENSE](file:///Users/rituparna/Documents/code/SecuredStorage/LICENSE) file for the full text.

```
SecuredStorage - PQC-Compliant Offline Password Vault
Copyright (C) 2026 Rituparna Ghosh

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
```


# Security Policy

The security and privacy of **SecuredStorage** users are paramount. Because SecuredStorage handles sensitive credentials and cryptographic keys, we take all vulnerability reports seriously and appreciate responsible disclosure from the security research community.

---

## Supported Versions

Only the latest release receives active security patches:

| Version | Supported |
| :--- | :---: |
| **1.2.x** | :white_check_mark: |
| < 1.2.0 | :x: |

We strongly recommend always running the latest version available on the [Releases](https://github.com/rituparnaprof/securedstorage/releases) page.

---

## Reporting a Vulnerability

If you discover a security vulnerability or cryptographic flaw in SecuredStorage, **please do not open a public GitHub issue**. Public disclosure before a patch is ready puts user credentials at risk.

Instead, report vulnerabilities privately through one of the following methods:

### Method 1: GitHub Private Vulnerability Reporting (Preferred)
1. Go to the repository's [Security Tab](https://github.com/rituparnaprof/securedstorage/security).
2. Click **"Report a vulnerability"** under Advisories.
3. Submit your findings securely. This opens a private communication channel directly with the maintainer.

### Method 2: Contact Maintainer
If Private Vulnerability Reporting is unavailable, send an email to:
**`334075393+rituparnaprof@users.noreply.github.com`** with the subject line:  
`[SECURITY] Vulnerability Report: SecuredStorage`

---

## What to Include in Your Report

To help us investigate and resolve the issue quickly, please include:

- **Type of Issue**: (e.g., Cryptographic flaw, RAM scraping / memory zeroization bypass, IPC command forgery, anti-debugging bypass).
- **Target Platform**: macOS (Apple Silicon / Intel), Windows 10/11, or Linux (X11 / Wayland).
- **Steps to Reproduce**: Clear, detailed steps or a minimal Proof of Concept (PoC) demonstrating the vulnerability.
- **Potential Impact**: What an attacker could achieve (e.g., read plaintext secrets, tamper with stored ciphertext).

---

## Our Vulnerability Response Process

1. **Acknowledgment**: We aim to acknowledge receipt of your report within **48 hours**.
2. **Investigation & Triage**: We will confirm the issue, assess severity, and determine an engineered fix in a private branch.
3. **Patch Release**: A patched release will be compiled and tagged across macOS, Linux, and Windows.
4. **Public Advisory & Credit**: Once the patch is published, a public security advisory will be issued, properly crediting the finder (unless you prefer anonymity).

---

## Security Architecture & Guarantees

For a detailed review of our threat modeling, in-memory RAM defense layers, cryptographic primitives (AES-256-GCM, Argon2id, ML-KEM-1024), and OS window shielding, please consult [ARCHITECTURE.md](ARCHITECTURE.md).

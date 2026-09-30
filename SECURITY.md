# Security Policy

## Maintenance Model: Best-Effort & Discretionary

**SecuredStorage** is an independent, personal open-source project provided on an **"AS IS"** basis under the GNU General Public License v3.0.

- **No Obligation to Patch**: The maintainer cares about software security and **may choose to review, investigate, or release updates at their sole discretion**. However, the maintainer is under **no obligation or legal commitment** to respond to, triage, or fix reported issues.
- **No Response SLA or Patch Guarantees**: There are no guaranteed response times, turnaround schedules, or commitments to publish maintenance releases.
- **Forks Encouraged**: If you identify a vulnerability, security flaw, or improvement that requires immediate remediation, you are encouraged to fork the repository under the **GNU General Public License v3.0** and apply your own fixes.

---

## Supported Versions

If security fixes or updates are ever published, they will only be applied to the **latest release**:

| Version | Status |
| :--- | :--- |
| **Latest Release (1.2.x)** | Best-effort / Discretionary updates only |
| < 1.2.0 | Unsupported (No backports) |

---

## Reporting a Vulnerability

If you discover a security vulnerability or cryptographic flaw and wish to disclose it responsibly, **please do not open a public GitHub issue**.

You may submit reports privately through:

### Method 1: GitHub Private Vulnerability Reporting (Preferred)
1. Navigate to the repository's [Security Tab](https://github.com/rituparnaprof/securedstorage/security).
2. Click **"Report a vulnerability"** under Advisories.
3. Submit your details privately.

### Method 2: Contact Maintainer
If Private Vulnerability Reporting is unavailable, you may email:  
**`334075393+rituparnaprof@users.noreply.github.com`** with the subject line:  
`[SECURITY] Vulnerability Report: SecuredStorage`

---

## Vulnerability Handling Expectations

- **Triage & Review**: Reports are received as voluntary, informational contributions. They will be reviewed only if and when the maintainer has the time and inclination to do so.
- **Remediation**: The decision whether to accept, modify code, or reject a reported issue rests entirely with the maintainer.
- **Credit**: If an update is released addressing a valid finding, credit will be happily attributed in release notes (unless the reporter prefers anonymity).

---

## Disclaimer of Warranty

As outlined in Sections 15 and 16 of the [GNU General Public License v3.0](LICENSE):
> The program is provided **"AS IS" without warranty of any kind**, either expressed or implied, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability.

For a detailed review of the vault's architectural threat model, RAM zeroization mechanisms, and cryptographic design, see [ARCHITECTURE.md](ARCHITECTURE.md).

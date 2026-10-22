<!-- Standard ARIA WIRE™ Open Source Repository Header -->

<p align="center">
  <a href="https://www.ariawave.tech">
    <img src="https://www.ariawave.tech/AriaLogoWhiteLarge.png" alt="ARIA Logo" width="180" />
  </a>
</p>

<p align="center">
  <a href="https://www.ariawave.tech/open-source?utm_source=github&utm_medium=repo-badge&utm_campaign=php2shell-scanner"><img src="https://img.shields.io/badge/ARIAWAVE-Security_Engineering-00f0ff?style=for-the-badge" alt="AriaWave Security Engineering" /></a>
  <a href="https://nvd.nist.gov/vuln/detail/CVE-2026-109618"><img src="https://img.shields.io/badge/CVE--2026--109618-CVSS_v4_9.2_CRITICAL-ef4444?style=for-the-badge" alt="CVE-2026-109618" /></a>
  <a href="https://nvd.nist.gov/vuln/detail/CVE-2026-109619"><img src="https://img.shields.io/badge/CVE--2026--109619-CVSS_v4_9.2_CRITICAL-ef4444?style=for-the-badge" alt="CVE-2026-109619" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-10b981?style=for-the-badge" alt="MIT License" /></a>
</p>

<h1 align="center">AriaWave PHP2Shell Vulnerability & Mitigation Scanner</h1>

<p align="center">
  <strong>Zero-Dependency Defensive Readiness, SAPI, Apache RLimitMEM & INI Override Auditor for CVE-2026-109618 & CVE-2026-109619 ("PHP2Shell") + Autonomous Agent Skill (`SKILL.md`).</strong><br/>
  Engineered by <a href="https://www.ariawave.tech">Aria Technology Group</a> ("Extreme Sports · Extreme Tech")
</p>

---

## Overview

On October 20, 2026, the PHP Group, Qualys Threat Research Unit (TRU), and NCSC-NL disclosed **PHP2Shell** (**`CVE-2026-109618`** and **`CVE-2026-109619`**, **CVSS v4.0: 9.2 Critical** / CVSS v3.1: 8.1 High) — two critical vulnerabilities in the PHP core runtime that allow unauthenticated remote attackers to corrupt memory and achieve **Remote Code Execution (RCE)** when out-of-memory conditions are triggered during request handling.

Because legacy **`mod_php`**, Apache **`RLimitMEM`** directives, and per-directory **`.htaccess` / `.user.ini` overrides** (`memory_limit = -1` or `ini_set('memory_limit', ...)`) dramatically lower the barrier to triggering out-of-memory corruption, version checks alone are insufficient during incident response.

**`ariawave-php2shell-scanner`** is a deterministic, **100% read-only Python 3 stdlib CLI auditor and autonomous agent `SKILL.md`** that inspects live PHP runtimes, Dockerfiles, `composer.json` manifests, Apache/FPM configs, and application source trees in seconds—with zero external pip dependencies and zero network payloads.

---

## Patched PHP Release Matrix

| PHP Branch | Affected Versions | Patched Release | Status |
|---|---|---|---|
| **PHP 8.5** | `< 8.5.12` | **`8.5.12`** | Supported — Upgrade Immediately |
| **PHP 8.4** | `< 8.4.27` | **`8.4.27`** | Supported — Upgrade Immediately |
| **PHP 8.3** | `< 8.3.36` | **`8.3.36`** | Supported — Upgrade Immediately |
| **PHP 8.2** | `< 8.2.35` | **`8.2.35`** | Security Support — Upgrade Immediately |
| **PHP ≤ 8.1** | All releases (`5.x`, `7.x`, `8.0`, `8.1`) | *End-of-Life (No upstream fix)* | Critical — Migrate to PHP 8.3+ or Vendor LTS |

---

## 5-Vector Defensive Inspection Architecture

1. **PHP Runtime & SemVer Patch Verification:** Evaluates active `php -v` binaries or explicit `--php-version` strings against the official fixed versions (`8.5.12`, `8.4.27`, `8.3.36`, `8.2.35`), flagging End-of-Life branches and Linux distro backport caveats.
2. **Container & Dependency Manifest Discovery:** Recursively scans `Dockerfile`, `Containerfile`, `docker-compose.yml`, and `composer.json` files for unpatched or floating image tags (e.g., `FROM php:8.3-fpm`, `FROM php:8.2-apache`).
3. **Apache `mod_php` & `RLimitMEM` Hazard Detection:** Identifies high-exposure in-process `LoadModule php_module` configurations and dangerous `RLimitMEM` directives that induce premature OOM states inside PHP workers.
4. **INI & `.htaccess` Memory-Limit Override Auditing:** Detects `memory_limit = -1` (unbounded), `memory_limit >= 1G`, `.htaccess` `php_value memory_limit` overrides, and application-level `ini_set('memory_limit', ...)` calls.
5. **cPanel EasyApache 4 & `php.d` Drop-In Mitigation Generator:** Emits NCSC-NL-aligned defensive `99-php2shell-mitigate.ini` drop-in files (`--emit-mitigation-ini`) to enforce conservative memory bounds while patching is scheduled.

---

## Quick Start

```bash
# 1. Run the built-in deterministic self-test suite
python3 php2shell_scanner.py --selftest

# 2. Check a specific PHP version string (JSON output)
python3 php2shell_scanner.py --php-version "8.3.35" --json

# 3. Audit a local web root, container repo, or /etc configuration tree
python3 php2shell_scanner.py --scan-dir /var/www --scan-dir /etc/apache2 --check-local-php

# 4. Generate a hardened drop-in INI mitigation file
python3 php2shell_scanner.py --emit-mitigation-ini ./99-php2shell-mitigate.ini
```

### Exit Codes for CI/CD & Fleet Orchestration
- `0` — **PASS / MITIGATED:** All checked PHP versions meet patched thresholds (`8.5.12+`, `8.4.27+`, `8.3.36+`, `8.2.35+`) and no high-risk config hazards were found.
- `1` — **VULNERABLE / CRITICAL:** Unpatched PHP runtime, EOL branch, `RLimitMEM` trigger, or unbounded `memory_limit = -1` detected.
- `2` — **REVIEW NEEDED:** Floating container tags (`php:8.3-fpm` without patch pin) or runtime `ini_set('memory_limit', ...)` overrides detected.

---

## Repository Structure

```text
ariawave-php2shell-scanner/
├── php2shell_scanner.py                 # Zero-dependency Python 3 CLI scanner + --selftest suite
├── SKILL.md                             # Autonomous Agent Skill specification (Hermes / Claude Code / Cursor)
├── scripts/
│   └── php2shell_scanner.py             # Skill-relative script entrypoint
├── mitigation/
│   └── 99-php2shell-mitigate.ini        # Ready-to-deploy defensive PHP.ini drop-in
├── LICENSE                              # MIT License
└── README.md                            # Documentation & CVE-2026-109618 / CVE-2026-109619 matrix
```

---

## References & Advisories

- **NCSC-NL Advisory & Mitigations:** [github.com/NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell)
- **Qualys Threat Research Unit (TRU):** [PHP Announces Critical Security Release for Two Vulnerabilities](https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/php-announces-critical-security-release-for-two-vulnerabilities)
- **Datadog Security Labs:** [PHP2Shell Critical Vulnerabilities in PHP](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- **AriaWave Security Advisory & Engineering Brief:** [ariawave.tech/blog/php2shell-cve-2026-109618-109619-scanner](https://www.ariawave.tech/blog/php2shell-cve-2026-109618-109619-scanner)

---

<p align="center">
  Licensed under the MIT License • Engineered by <a href="https://www.ariawave.tech">Aria Technology Group</a> ("Extreme Sports · Extreme Tech")
</p>

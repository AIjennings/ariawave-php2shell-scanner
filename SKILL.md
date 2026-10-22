---
name: php2shell-vulnerability-scanner
description: "Defensive readiness, version, SAPI, and INI mitigation auditor for PHP2Shell critical RCE vulnerabilities (CVE-2026-109618 and CVE-2026-109619, CVSSv4 9.2). Built by AriaWave / Aria Technology Group."
version: 1.0.0
author: Aria Technology Group (https://www.ariawave.tech)
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [Security, PHP, PHP2Shell, CVE-2026-109618, CVE-2026-109619, Audit, Hardening, AriaWave]
---

# AriaWave PHP2Shell Readiness & Mitigation Scanner (`CVE-2026-109618` / `CVE-2026-109619`)

Production defensive audit skill and zero-dependency Python 3.10+ CLI tool engineered by **[Aria Technology Group](https://www.ariawave.tech)** (`AriaWave`) to detect exposure to the **PHP2Shell** critical unauthenticated remote code execution vulnerabilities (**CVE-2026-109618** and **CVE-2026-109619**, CVSS v4.0 **9.2**) and validate temporary INI/SAPI mitigations across local hosts, containers, cPanel EasyApache 4 fleets, and authorized web endpoints.

> **Safety & Non-Exploitation Guarantee:** This tool is strictly **defensive and non-destructive**. It performs zero active exploitation, sends no malicious payloads, and defaults to read-only inspection and dry-run mitigation generation.

---

## Threat Intelligence Summary (PHP2Shell — Disclosed Oct 20–21, 2026)

| CVE ID | CVSS v4.0 | Vulnerability Class | Root Cause & Trigger Vector | Highest-Risk SAPI |
| :--- | :--- | :--- | :--- | :--- |
| **CVE-2026-109618** | **9.2 (Critical)** | Unauthenticated RCE via Out-of-Memory (OOM) Corruption | Memory corruption during request cleanup when PHP hits an OOM condition (amplified by OS `RLIMIT_AS`/`RLIMIT_DATA` or uncapped `post_max_size`). | **Apache `mod_php`** (triggers before application code runs); also affects `php-fpm`, `php-cgi`, FrankenPHP, LiteSpeed |
| **CVE-2026-109619** | **9.2 (Critical)** | Unauthenticated RCE via Use-After-Free (Stale Request State) | Stale request-owned global state (`session.upload_progress`) retained and reused by a subsequent request on the same worker process. | Persistent worker SAPIs (`mod_php`, `php-fpm`, FrankenPHP, LiteSpeed) |

### Patched PHP Releases (Published 21 October 2026)

| PHP Branch | Vulnerable Versions | Patched Release | Status |
| :--- | :--- | :--- | :--- |
| **PHP 8.5** | `8.5.0` – `8.5.11` | **`8.5.12`** | Active support — update immediately |
| **PHP 8.4** | `8.4.0` – `8.4.26` | **`8.4.27`** | Active support — update immediately |
| **PHP 8.3** | `8.3.0` – `8.3.35` | **`8.3.36`** | Security support — update immediately |
| **PHP 8.2** | `8.2.0` – `8.2.34` | **`8.2.35`** | Security support — update immediately |
| **PHP <= 8.1** | `8.1.x`, `8.0.x`, `7.4.x`, `<= 7.3` | Vendor / LTS Backport Required | End-of-Life upstream (PHP published source backports for 7.4/8.0/8.1; check OS vendor packages) |

---

## Core Audit & Mitigation Capabilities

1. **Runtime, Container & Manifest Version Audit (`--version` / `--scan-dir`):**
   - Evaluates live `php -v` binaries, `Dockerfile` (`FROM php:...`), `docker-compose.yml`, `composer.json` / `composer.lock`, and cPanel EasyApache (`ea-php*`) versions against the October 21, 2026 fixed release thresholds.
2. **SAPI & INI Mitigation Audit (`--scan-dir`):**
   - Flags Apache `mod_php` (`LoadModule php_module`, `AddHandler application/x-httpd-php`) where exploitation can trigger before application code executes.
   - Verifies `session.upload_progress.enabled = 0` (`CVE-2026-109619` mitigation).
   - Verifies bounded `post_max_size` and `upload_max_filesize` (`<= 32M` default ceiling for `CVE-2026-109618`).
   - Flags dangerous Apache `RLimitMEM` (`RLIMIT_AS` / `RLIMIT_DATA`) directives that force PHP into the vulnerable OOM cleanup code path.
   - Detects per-directory `.htaccess` (`php_value` / `php_flag`), `.user.ini`, and local `php.ini` overrides that could silently undo global `php.d` mitigations.
   - Checks `fatal_error_backtraces = Off` on PHP 8.5 runtimes.
3. **Passive Authorized Header Inspection (`--url`):**
   - Issues a single standard HTTP `HEAD` (or `GET` fallback) request to operator-authorized URLs to check passive `X-Powered-By` and `Server` headers for exposed unpatched PHP versions.
4. **Deterministic Drop-In Mitigation Generator (`--emit-dropin`):**
   - Outputs the `zzzzzzzz-cve-2026-109618-109619.ini` hardening drop-in configuration (loaded lexicographically last in `php.d/`) to apply official temporary mitigations while patching is scheduled.

---

## Quickstart CLI Commands

```bash
# 1. Run the built-in deterministic self-test suite
python scripts/php2shell_scanner.py --selftest

# 2. Check a specific PHP version string
python scripts/php2shell_scanner.py --version "8.4.26"

# 3. Audit a project directory, server config tree (/etc/php, /etc/apache2, /var/www), or repo
python scripts/php2shell_scanner.py --scan-dir /path/to/project

# 4. Passively inspect an authorized web endpoint's response headers
python scripts/php2shell_scanner.py --url https://example.com

# 5. Output the temporary php.d drop-in mitigation file (zzzzzzzz-cve-2026-109618-109619.ini)
python scripts/php2shell_scanner.py --emit-dropin --post-max 32M
```

---

## Remediation Playbook

1. **Primary Fix (Mandatory):** Upgrade PHP to **`8.5.12`**, **`8.4.27`**, **`8.3.36`**, or **`8.2.35`** (or verify your Linux distribution's backported security package changelog for `CVE-2026-109618` and `CVE-2026-109619`) and restart all web/PHP-FPM workers.
2. **Eliminate `mod_php` Where Possible:** Migrate Apache `mod_php` deployments to isolated `php-fpm` pools.
3. **Temporary Drop-In Hardening (Only Until Patched):**
   Place `zzzzzzzz-cve-2026-109618-109619.ini` in your active `php.d` / `conf.d` scan directory and restart Apache / PHP-FPM:
   ```ini
   ; Temporary mitigation for CVE-2026-109618 & CVE-2026-109619 (PHP2Shell)
   ; Generated by AriaWave PHP2Shell Readiness Scanner (https://www.ariawave.tech)
   session.upload_progress.enabled = 0
   post_max_size = 32M
   upload_max_filesize = 32M
   fatal_error_backtraces = 0
   ```
4. **Remove Apache `RLimitMEM`:** Do not use OS-level `RLimitMEM` (`RLIMIT_AS` / `RLIMIT_DATA`) to constrain PHP worker memory; it triggers the vulnerable out-of-memory cleanup path.

## References

- [PHP.net Official Security Advisory (2026-10-21)](https://www.php.net/archive/2026.php#2026-10-21-5)
- [CERT-EU Security Advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/)
- [NCSC-NL PHP2Shell Operational Guidance](https://github.com/NCSC-NL/php2shell)
- [NSA Advisory: Critical Patches Recommended for PHP Vulnerabilities](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4630238/nsa-advisory-critical-patches-recommended-for-php-vulnerabilities/)

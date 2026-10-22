#!/usr/bin/env python3
"""
php2shell_scanner.py
AriaWave Defensive Readiness, Version, SAPI & INI Mitigation Scanner for PHP2Shell
(CVE-2026-109618 & CVE-2026-109619 — CVSS v4.0 9.2 Critical)

Built by Aria Technology Group (https://www.ariawave.tech)
License: MIT

SAFETY & NON-EXPLOITATION NOTICE:
This tool is strictly defensive and non-destructive. It performs version comparisons,
static configuration/manifest audits (php.ini, .htaccess, .user.ini, Apache/Nginx,
Dockerfile, composer), passive HTTP header banner checks on authorized endpoints,
and dry-run drop-in mitigation generation. It never transmits exploit payloads.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ADVISORY_DATE = "2026-10-21"
CVES = ["CVE-2026-109618", "CVE-2026-109619"]

# Fixed PHP versions published on 2026-10-21 per PHP.net / CERT-EU 2026-018 / NCSC-NL
PATCHED_MIN_PATCH: Dict[Tuple[int, int], int] = {
    (8, 5): 12,  # 8.5.12+
    (8, 4): 27,  # 8.4.27+
    (8, 3): 36,  # 8.3.36+
    (8, 2): 35,  # 8.2.35+
}

EOL_SOURCE_BACKPORT_BRANCHES = {(8, 1), (8, 0), (7, 4)}

VERSION_REGEX = re.compile(r"(?<!\d)(?:php[/-]?|v)?(\d+)\.(\d+)\.(\d+)(?:-[\w.+~-]+)?(?!\d)", re.IGNORECASE)
DOCKER_PHP_IMAGE_REGEX = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?php:(\d+\.\d+(?:\.\d+)?(?:-[\w.-]+)?)",
    re.IGNORECASE | re.MULTILINE,
)
MOD_PHP_REGEX = re.compile(
    r"(LoadModule\s+php\d*_module|AddHandler\s+application/x-httpd-php|SetHandler\s+application/x-httpd-php|libphp\d*\.so)",
    re.IGNORECASE,
)
RLIMIT_MEM_REGEX = re.compile(r"^\s*RLimitMEM\b", re.IGNORECASE | re.MULTILINE)
HTACCESS_PHP_OVERRIDE_REGEX = re.compile(
    r"^\s*php_(?:admin_)?(?:value|flag)\s+(session\.upload_progress\.enabled|post_max_size|upload_max_filesize|memory_limit|fatal_error_backtraces)\s+([^\r\n#;]+)",
    re.IGNORECASE | re.MULTILINE,
)
INI_DIRECTIVE_REGEX = re.compile(
    r"^\s*(session\.upload_progress\.enabled|post_max_size|upload_max_filesize|memory_limit|fatal_error_backtraces)\s*=\s*([^\r\n;#]+)",
    re.IGNORECASE | re.MULTILINE,
)


def parse_php_shorthand_bytes(value: str) -> int:
    """Convert PHP shorthand byte strings (e.g. 32M, 8M, 1G, 0, -1) to integer bytes."""
    cleaned = value.strip().strip('"').strip("'").upper()
    if cleaned in ("-1", "0"):
        return int(cleaned)
    match = re.match(r"^(\d+)\s*([KMG]?)$", cleaned)
    if not match:
        return -2
    num = int(match.group(1))
    unit = match.group(2)
    if unit == "K":
        return num * 1024
    if unit == "M":
        return num * 1024 * 1024
    if unit == "G":
        return num * 1024 * 1024 * 1024
    return num


def evaluate_php_version(version_str: str) -> Dict[str, Any]:
    """Evaluate a PHP version string against CVE-2026-109618 & CVE-2026-109619 fixed releases."""
    match = VERSION_REGEX.search(version_str)
    if not match:
        branch_match = re.search(r"(?<!\d)(\d+)\.(\d+)(?!\.\d)", version_str)
        if branch_match:
            major, minor = int(branch_match.group(1)), int(branch_match.group(2))
            branch = (major, minor)
            if branch in PATCHED_MIN_PATCH:
                fixed = f"{major}.{minor}.{PATCHED_MIN_PATCH[branch]}"
                return {
                    "input": version_str,
                    "parsed_version": f"{major}.{minor}.x",
                    "status": "REVIEW_REQUIRED",
                    "severity": "HIGH",
                    "cves": CVES,
                    "patched_release": fixed,
                    "detail": f"Floating branch tag '{major}.{minor}' detected without explicit patch level. Pin to >= {fixed}.",
                }
        return {
            "input": version_str,
            "parsed_version": None,
            "status": "UNKNOWN",
            "severity": "INFO",
            "cves": CVES,
            "patched_release": None,
            "detail": "Could not parse a semantic PHP version (X.Y.Z).",
        }

    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
    parsed = f"{major}.{minor}.{patch}"
    branch = (major, minor)

    # Distro backport hint detection (e.g., +deb12u, -ubuntu, .el9)
    has_distro_suffix = bool(re.search(r"(ubuntu|deb|el\d|alpine|remi|sury)", version_str, re.IGNORECASE))

    if branch in PATCHED_MIN_PATCH:
        min_safe = PATCHED_MIN_PATCH[branch]
        fixed_str = f"{major}.{minor}.{min_safe}"
        if patch >= min_safe:
            return {
                "input": version_str,
                "parsed_version": parsed,
                "status": "PATCHED",
                "severity": "SAFE",
                "cves": CVES,
                "patched_release": fixed_str,
                "detail": f"PHP {parsed} meets or exceeds fixed release {fixed_str}.",
            }
        return {
            "input": version_str,
            "parsed_version": parsed,
            "status": "VULNERABLE",
            "severity": "CRITICAL",
            "cves": CVES,
            "patched_release": fixed_str,
            "distro_backport_hint": has_distro_suffix,
            "detail": (
                f"PHP {parsed} is below fixed release {fixed_str} (CVE-2026-109618 & CVE-2026-109619, CVSSv4 9.2). "
                + (
                    "Distro package suffix detected — verify vendor security changelog if backported."
                    if has_distro_suffix
                    else f"Upgrade immediately to {fixed_str}+."
                )
            ),
        }

    if (major, minor) > (8, 5):
        return {
            "input": version_str,
            "parsed_version": parsed,
            "status": "PATCHED",
            "severity": "SAFE",
            "cves": CVES,
            "patched_release": parsed,
            "detail": f"PHP {parsed} is newer than the 8.5 advisory baseline.",
        }

    if branch in EOL_SOURCE_BACKPORT_BRANCHES or major < 8:
        return {
            "input": version_str,
            "parsed_version": parsed,
            "status": "VULNERABLE_EOL",
            "severity": "CRITICAL",
            "cves": CVES,
            "patched_release": "8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or vendor LTS backport)",
            "distro_backport_hint": has_distro_suffix,
            "detail": (
                f"PHP {parsed} is End-of-Life upstream and vulnerable to CVE-2026-109618 & CVE-2026-109619 unless "
                "patched via vendor LTS backport or PHP minimal source backport (7.4/8.0/8.1)."
            ),
        }

    return {
        "input": version_str,
        "parsed_version": parsed,
        "status": "UNKNOWN",
        "severity": "MEDIUM",
        "cves": CVES,
        "patched_release": None,
        "detail": f"Unrecognized PHP branch {parsed}.",
    }


def audit_config_text(content: str, source_label: str = "config", post_max_ceiling_mb: int = 32) -> List[Dict[str, Any]]:
    """Audit PHP INI, .htaccess, Apache/Nginx config, or Dockerfile content for PHP2Shell risks."""
    findings: List[Dict[str, Any]] = []
    ceiling_bytes = post_max_ceiling_mb * 1024 * 1024

    # 1. Check Dockerfile PHP base images
    for match in DOCKER_PHP_IMAGE_REGEX.finditer(content):
        tag = match.group(1)
        ver_eval = evaluate_php_version(tag)
        sapi_note = "mod_php (Apache)" if "apache" in tag.lower() else "container runtime"
        if ver_eval["status"] in ("VULNERABLE", "VULNERABLE_EOL", "REVIEW_REQUIRED"):
            findings.append({
                "source": source_label,
                "rule": "PHP2SHELL-DOCKER-IMAGE",
                "severity": "CRITICAL" if "apache" in tag.lower() else ver_eval["severity"],
                "detail": f"Dockerfile image 'php:{tag}' ({sapi_note}): {ver_eval['detail']}",
            })

    # 2. Check Apache mod_php exposure (highest risk per PHP.net advisory)
    if MOD_PHP_REGEX.search(content):
        findings.append({
            "source": source_label,
            "rule": "PHP2SHELL-MOD-PHP-SAPI",
            "severity": "CRITICAL",
            "detail": (
                "Apache mod_php handler detected. PHP warns mod_php carries the highest risk for "
                "CVE-2026-109618 because exploitation can trigger before application code runs. "
                "Update to 8.5.12/8.4.27/8.3.36/8.2.35 immediately or migrate to isolated php-fpm pools."
            ),
        })

    # 3. Check Apache RLimitMEM hazard
    if RLIMIT_MEM_REGEX.search(content):
        findings.append({
            "source": source_label,
            "rule": "PHP2SHELL-APACHE-RLIMITMEM",
            "severity": "HIGH",
            "detail": (
                "Apache RLimitMEM directive detected. Per PHP/NCSC-NL advisory, OS-level RLIMIT_AS/RLIMIT_DATA "
                "triggers the vulnerable out-of-memory cleanup code path (CVE-2026-109618). Remove RLimitMEM."
            ),
        })

    # 4. Check INI and .htaccess directives
    directives: List[Tuple[str, str, bool]] = []
    for m in INI_DIRECTIVE_REGEX.finditer(content):
        directives.append((m.group(1).lower(), m.group(2).strip(), False))
    for m in HTACCESS_PHP_OVERRIDE_REGEX.finditer(content):
        directives.append((m.group(1).lower(), m.group(2).strip(), True))

    for key, val, is_htaccess in directives:
        clean_val = val.strip('"').strip("'").lower()
        override_prefix = "Per-directory .htaccess override: " if is_htaccess else ""

        if key == "session.upload_progress.enabled":
            if clean_val in ("1", "on", "true", "yes"):
                findings.append({
                    "source": source_label,
                    "rule": "PHP2SHELL-UPLOAD-PROGRESS-ENABLED",
                    "severity": "HIGH",
                    "detail": (
                        f"{override_prefix}session.upload_progress.enabled is set to '{val}'. "
                        "Set session.upload_progress.enabled = 0 to mitigate CVE-2026-109619 stale state reuse."
                    ),
                })
        elif key in ("post_max_size", "upload_max_filesize"):
            size_bytes = parse_php_shorthand_bytes(val)
            if size_bytes == 0:
                findings.append({
                    "source": source_label,
                    "rule": "PHP2SHELL-UNLIMITED-POST-SIZE",
                    "severity": "CRITICAL",
                    "detail": (
                        f"{override_prefix}{key} is set to '0' (unlimited), allowing large payloads "
                        "to trigger OOM corruption (CVE-2026-109618). Cap to <= 32M (or 8M if no uploads needed)."
                    ),
                })
            elif size_bytes > ceiling_bytes:
                findings.append({
                    "source": source_label,
                    "rule": "PHP2SHELL-HIGH-POST-SIZE",
                    "severity": "MEDIUM",
                    "detail": (
                        f"{override_prefix}{key} is '{val}' (> {post_max_ceiling_mb}M recommended temporary ceiling "
                        "for CVE-2026-109618 mitigation)."
                    ),
                })
        elif key == "fatal_error_backtraces":
            if clean_val in ("1", "on", "true", "yes"):
                findings.append({
                    "source": source_label,
                    "rule": "PHP2SHELL-PHP85-FATAL-BACKTRACES",
                    "severity": "MEDIUM",
                    "detail": (
                        f"{override_prefix}fatal_error_backtraces is enabled ('{val}'). "
                        "Review PHP 8.5 advisory guidance and disable fatal_error_backtraces during mitigation."
                    ),
                })

    return findings


def scan_directory(root_dir: Path, post_max_ceiling_mb: int = 32) -> Dict[str, Any]:
    """Recursively scan a directory for PHP configurations, Dockerfiles, and composer manifests."""
    target_filenames = {
        "php.ini",
        ".user.ini",
        ".htaccess",
        "httpd.conf",
        "apache2.conf",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "composer.json",
        "composer.lock",
    }
    files_scanned = 0
    findings: List[Dict[str, Any]] = []
    version_checks: List[Dict[str, Any]] = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Skip noisy vendor/node_modules/.git directories
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", ".next", ".venv", "venv", "__pycache__"}]
        for fname in filenames:
            lower_name = fname.lower()
            is_conf_ext = lower_name.endswith((".ini", ".conf"))
            if lower_name not in target_filenames and not is_conf_ext and not lower_name.startswith("dockerfile"):
                continue
            fpath = Path(dirpath) / fname
            try:
                if fpath.stat().st_size > 2 * 1024 * 1024:
                    continue
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            files_scanned += 1
            rel_label = str(fpath.relative_to(root_dir)) if fpath != root_dir else fname

            if lower_name == "composer.lock":
                try:
                    lock_data = json.loads(text)
                    plat_php = lock_data.get("platform", {}).get("php")
                    if isinstance(plat_php, str):
                        ev = evaluate_php_version(plat_php)
                        ev["source"] = rel_label
                        version_checks.append(ev)
                except json.JSONDecodeError:
                    pass
            elif lower_name == "composer.json":
                try:
                    comp_data = json.loads(text)
                    req_php = comp_data.get("config", {}).get("platform", {}).get("php") or comp_data.get("require", {}).get("php")
                    if isinstance(req_php, str):
                        ev = evaluate_php_version(req_php)
                        ev["source"] = rel_label
                        version_checks.append(ev)
                except json.JSONDecodeError:
                    pass
            else:
                findings.extend(audit_config_text(text, source_label=rel_label, post_max_ceiling_mb=post_max_ceiling_mb))

    vulnerable_versions = [v for v in version_checks if v["status"] in ("VULNERABLE", "VULNERABLE_EOL")]
    critical_or_high = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]

    return {
        "scan_root": str(root_dir),
        "advisory_baseline": ADVISORY_DATE,
        "cves": CVES,
        "files_scanned": files_scanned,
        "version_checks": version_checks,
        "finding_count": len(findings),
        "findings": findings,
        "passed_readiness": len(vulnerable_versions) == 0 and len(critical_or_high) == 0,
    }


def inspect_passive_http_headers(url: str, timeout: int = 8) -> Dict[str, Any]:
    """Passively inspect HTTP response headers (X-Powered-By / Server) on an authorized URL."""
    ctx = ssl.create_default_context()
    headers = {"User-Agent": "AriaWave-PHP2Shell-Readiness-Auditor/1.0 (+https://www.ariawave.tech)"}
    req = urllib.request.Request(url, headers=headers, method="HEAD")
    resp_headers: Dict[str, str] = {}
    status_code: Optional[int] = None

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status_code = resp.status
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        status_code = e.code
        resp_headers = {k.lower(): v for k, v in e.headers.items()}
    except Exception as e:
        return {
            "url": url,
            "reachable": False,
            "error": str(e),
            "exposed_php_version": None,
            "evaluation": None,
        }

    x_powered_by = resp_headers.get("x-powered-by", "")
    server_hdr = resp_headers.get("server", "")
    combined = f"{x_powered_by} {server_hdr}".strip()

    php_match = re.search(r"PHP/(\d+\.\d+\.\d+(?:-[\w.+~-]+)?)", combined, re.IGNORECASE)
    mod_php_exposed = bool(re.search(r"Apache.*PHP/", server_hdr, re.IGNORECASE))

    eval_result = evaluate_php_version(php_match.group(1)) if php_match else None

    return {
        "url": url,
        "reachable": True,
        "http_status": status_code,
        "server_header": server_hdr or None,
        "x_powered_by": x_powered_by or None,
        "mod_php_banner_detected": mod_php_exposed,
        "exposed_php_version": php_match.group(1) if php_match else None,
        "evaluation": eval_result,
        "recommendation": (
            "PHP version banner is not exposed in HTTP headers (good practice; verify runtime locally with --scan-dir or php -v)."
            if not php_match
            else eval_result["detail"]
        ),
    }


def generate_dropin_ini(post_max: str = "32M", upload_max: Optional[str] = None, memory_unlimited: bool = False) -> str:
    """Generate the temporary php.d drop-in mitigation file per PHP/NCSC-NL guidance."""
    up_max = upload_max or post_max
    lines = [
        "; =============================================================================",
        "; Temporary Mitigation Drop-In for CVE-2026-109618 & CVE-2026-109619 (PHP2Shell)",
        "; Generated by AriaWave PHP2Shell Readiness Scanner (https://www.ariawave.tech)",
        "; File target: etc/php.d/zzzzzzzz-cve-2026-109618-109619.ini",
        "; IMPORTANT: Per php.net advisory (2026-10-21), ONLY updating to PHP 8.5.12,",
        "; 8.4.27, 8.3.36, or 8.2.35 is a complete fix. Restart PHP-FPM/Apache after placing.",
        "; =============================================================================",
        "",
        "; Mitigate CVE-2026-109619 (stale upload_progress global state across requests)",
        "session.upload_progress.enabled = 0",
        "",
        "; Mitigate CVE-2026-109618 (bound request body size to reduce OOM trigger surface)",
        f"post_max_size = {post_max}",
        f"upload_max_filesize = {up_max}",
        "",
        "; Mitigate PHP 8.5 fatal error backtrace OOM amplification",
        "fatal_error_backtraces = 0",
    ]
    if memory_unlimited:
        lines.extend([
            "",
            "; Optional: trade memory availability to avoid PHP-level OOM cleanup trigger",
            "memory_limit = -1",
        ])
    return "\n".join(lines) + "\n"


def detect_local_php_binary() -> Optional[Dict[str, Any]]:
    """Check if a local php binary is on PATH and evaluate its version."""
    php_bin = shutil.which("php")
    if not php_bin:
        return None
    try:
        proc = subprocess.run([php_bin, "-v"], capture_output=True, text=True, timeout=5)
        first_line = (proc.stdout or proc.stderr).splitlines()[0] if (proc.stdout or proc.stderr) else ""
        return {
            "binary": php_bin,
            "banner": first_line,
            "evaluation": evaluate_php_version(first_line),
        }
    except Exception as e:
        return {"binary": php_bin, "error": str(e)}


def run_selftest() -> int:
    """Deterministic self-test suite verifying all PHP2Shell detection & mitigation rules."""
    # 1. Version matrix assertions across all 4 supported branches + EOL
    assert evaluate_php_version("8.5.11")["status"] == "VULNERABLE"
    assert evaluate_php_version("8.5.12")["status"] == "PATCHED"
    assert evaluate_php_version("8.4.26")["status"] == "VULNERABLE"
    assert evaluate_php_version("8.4.27")["status"] == "PATCHED"
    assert evaluate_php_version("8.3.35")["status"] == "VULNERABLE"
    assert evaluate_php_version("8.3.36")["status"] == "PATCHED"
    assert evaluate_php_version("8.2.34")["status"] == "VULNERABLE"
    assert evaluate_php_version("8.2.35")["status"] == "PATCHED"
    assert evaluate_php_version("8.1.31")["status"] == "VULNERABLE_EOL"
    assert evaluate_php_version("7.4.33")["status"] == "VULNERABLE_EOL"

    # 2. Config & SAPI audit assertions
    vulnerable_conf = """
    FROM php:8.3.35-apache
    LoadModule php_module modules/libphp8.so
    RLimitMEM 134217728
    session.upload_progress.enabled = On
    post_max_size = 0
    fatal_error_backtraces = On
    php_value session.upload_progress.enabled 1
    """
    findings = audit_config_text(vulnerable_conf, source_label="selftest-unsafe.conf")
    rules_hit = {f["rule"] for f in findings}
    assert "PHP2SHELL-DOCKER-IMAGE" in rules_hit
    assert "PHP2SHELL-MOD-PHP-SAPI" in rules_hit
    assert "PHP2SHELL-APACHE-RLIMITMEM" in rules_hit
    assert "PHP2SHELL-UPLOAD-PROGRESS-ENABLED" in rules_hit
    assert "PHP2SHELL-UNLIMITED-POST-SIZE" in rules_hit
    assert "PHP2SHELL-PHP85-FATAL-BACKTRACES" in rules_hit

    # 3. Hardened config assertions
    hardened_conf = """
    FROM php:8.4.27-fpm-alpine
    session.upload_progress.enabled = 0
    post_max_size = 32M
    upload_max_filesize = 32M
    fatal_error_backtraces = 0
    """
    safe_findings = audit_config_text(hardened_conf, source_label="selftest-safe.conf")
    assert len(safe_findings) == 0, f"Expected 0 findings on hardened config, got: {safe_findings}"

    # 4. Drop-in INI generator assertion
    dropin = generate_dropin_ini(post_max="16M")
    assert "session.upload_progress.enabled = 0" in dropin
    assert "post_max_size = 16M" in dropin
    assert len(audit_config_text(dropin, source_label="generated-dropin.ini")) == 0

    print("[PASS] php2shell_scanner.py --selftest: all CVE-2026-109618 / CVE-2026-109619 assertions passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AriaWave PHP2Shell (CVE-2026-109618 & CVE-2026-109619) Readiness & Mitigation Scanner"
    )
    parser.add_argument("--selftest", action="store_true", help="Run deterministic self-test suite")
    parser.add_argument("--version", type=str, help="Evaluate a specific PHP version string (e.g. '8.4.26')")
    parser.add_argument("--scan-dir", type=str, help="Scan a directory for PHP configs, Dockerfiles, and manifests")
    parser.add_argument("--url", type=str, help="Passively inspect HTTP headers on an authorized URL")
    parser.add_argument("--emit-dropin", action="store_true", help="Output temporary php.d mitigation drop-in INI")
    parser.add_argument("--post-max", type=str, default="32M", help="post_max_size ceiling for drop-in (default: 32M)")
    parser.add_argument("--memory-unlimited", action="store_true", help="Include memory_limit = -1 in drop-in")
    args = parser.parse_args()

    if args.selftest:
        return run_selftest()

    if args.emit_dropin:
        print(generate_dropin_ini(post_max=args.post_max, memory_unlimited=args.memory_unlimited), end="")
        return 0

    if args.version:
        res = evaluate_php_version(args.version)
        print(json.dumps(res, indent=2))
        return 0 if res["status"] == "PATCHED" else 1

    if args.scan_dir:
        res = scan_directory(Path(args.scan_dir).resolve())
        print(json.dumps(res, indent=2))
        return 0 if res["passed_readiness"] else 1

    if args.url:
        res = inspect_passive_http_headers(args.url)
        print(json.dumps(res, indent=2))
        return 0

    # Default summary output + local php binary check if present
    local_php = detect_local_php_binary()
    print(
        json.dumps(
            {
                "status": "ready",
                "tool": "php2shell_scanner.py",
                "vendor": "AriaWave / Aria Technology Group (https://www.ariawave.tech)",
                "advisory_date": ADVISORY_DATE,
                "cves": CVES,
                "patched_releases": ["8.5.12", "8.4.27", "8.3.36", "8.2.35"],
                "local_php_runtime": local_php,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

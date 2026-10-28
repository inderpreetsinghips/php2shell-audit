#!/usr/bin/env python3
"""
php2shell_audit.py — Detection & exposure auditor for PHP2Shell
================================================================

PHP2Shell is the common name for two critical PHP engine vulnerabilities
disclosed in October 2026:

    CVE-2026-109618  RCE via out-of-memory corruption      (CVSS 9.2)
    CVE-2026-109619  RCE via stale global state (heap UAF)  (CVSS 9.2)

Both are unauthenticated and have been exploited in the wild. They live in
the PHP *interpreter*, not in application source code, so the reliable signal
is which PHP build is serving requests plus the runtime configuration that
amplifies exposure — NOT "vulnerable looking" PHP source lines.

This tool is a DEFENSIVE detector. It answers "is this vulnerable, and how
exposed is it?" using:
  * version fingerprinting (compared to the fixed releases), and
  * configuration risk assessment.

It is deliberately NON-INTRUSIVE: it never sends exploit payloads, never
triggers the memory-corruption condition, and never attempts code execution.
A version + exposure verdict is how Qualys/Nessus/etc. detect this class of
engine bug, and it is sufficient for triage and patch-tracking.

Fixed versions (patch and restart all workers):
    8.2.x -> 8.2.35      8.4.x -> 8.4.27
    8.3.x -> 8.3.36      8.5.x -> 8.5.12
    7.4 / 8.0 / 8.1 -> no mainline fix (use distro backport or upgrade)
    7.3 and older       -> end of life, upgrade

----------------------------------------------------------------------
AUTHORIZED USE ONLY. Live host / fleet scanning must only be run against
systems you own or have explicit written permission to assess. Unauthorized
scanning may be illegal. See the LICENSE / README notice.
----------------------------------------------------------------------

Standard library only. Python 3.8+. No third-party dependencies.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import ssl
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple

__version__ = "1.1.0"

# ---------------------------------------------------------------------------
# Vulnerability metadata
# ---------------------------------------------------------------------------

CVES = ["CVE-2026-109618", "CVE-2026-109619"]

# First FIXED patch level for each supported branch (major, minor) -> patch.
# A version on that branch is vulnerable if its patch < this value.
FIXED_PATCH = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}

# Branches that are affected but have NO mainline upstream fix.
NO_UPSTREAM_FIX = {(8, 1), (8, 0), (7, 4)}

# Severity levels (ordered for ranking).
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

REMEDIATION = {
    "patch": (
        "Upgrade to the fixed release for your branch "
        "(8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) and RESTART every PHP worker "
        "(FPM pool, Apache, etc.) — the running process keeps the old code "
        "until restarted."
    ),
    "eol": (
        "This branch is end-of-life with no fix. Upgrade to a supported, "
        "patched branch."
    ),
    "no_upstream": (
        "No mainline PHP fix exists for this branch. Use your distribution's "
        "backported package (e.g. RHEL/Debian security update) or PHP's "
        "minimal source backport, then restart workers. Verify the package "
        "changelog references the CVEs — the version number may not change."
    ),
    "upload_progress": (
        "Set session.upload_progress.enabled=0 in php.ini / the FPM pool / "
        "server config (NOT via ini_set() or .user.ini) and restart workers. "
        "This closes one confirmed path for CVE-2026-109619 but is not a "
        "complete mitigation on its own — patching is."
    ),
    "fatal_backtraces": (
        "On PHP 8.5, set fatal_error_backtraces=0 administratively and "
        "restart workers — a confirmed mod_php path."
    ),
    "request_limits": (
        "Constrain request size/complexity at the proxy and in PHP "
        "(post_max_size, upload_max_filesize, max_input_nesting_level, "
        "max_file_uploads). These reduce exploitability but do not replace "
        "patching."
    ),
    "mod_php": (
        "mod_php (Apache prefork) is rated the highest-risk SAPI for "
        "PHP2Shell. Prioritise patching these hosts; consider PHP-FPM."
    ),
}

AUTH_NOTICE = (
    "AUTHORIZED USE ONLY — scan only systems you own or are explicitly "
    "permitted to assess."
)

# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    severity: str                       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    target: str                         # file path or host
    detail: str
    evidence: str = ""                  # the matched line/header
    php_version: Optional[str] = None
    verdict: Optional[str] = None       # VULNERABLE / FIXED / etc.
    remediation: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=lambda: list(CVES))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Version engine  (Task 1)
# ---------------------------------------------------------------------------

# Verdict constants
V_VULNERABLE = "VULNERABLE"
V_VULNERABLE_EOL = "VULNERABLE_EOL"
V_VULNERABLE_NO_UPSTREAM = "VULNERABLE_NO_UPSTREAM_FIX"
V_FIXED = "FIXED"
V_UNKNOWN_PATCH = "BRANCH_AFFECTED_PATCH_UNKNOWN"
V_UNKNOWN = "UNKNOWN"


_VER_RE = re.compile(r"(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?")


def parse_php_version(text: str) -> Optional[Tuple[int, int, Optional[int]]]:
    """Extract (major, minor, patch|None) from arbitrary text.

    Handles 'PHP/8.3.12', '8.3', 'php:8.4.2-fpm-alpine', '8.2.35', etc.
    Returns None if no plausible PHP version is present.
    """
    if not text:
        return None
    for m in _VER_RE.finditer(text):
        major = int(m.group(1))
        minor = int(m.group(2))
        patch = int(m.group(3)) if m.group(3) is not None else None
        # Only treat 5.x / 7.x / 8.x (and future 9.x) as PHP versions.
        if major in (5, 7, 8, 9):
            return (major, minor, patch)
    return None


def classify_version(ver: Tuple[int, int, Optional[int]]) -> Tuple[str, str]:
    """Return (verdict, human_explanation) for a parsed version tuple."""
    major, minor, patch = ver
    branch = (major, minor)

    # End of life / no fix branches.
    if major < 7 or (major == 7 and minor <= 3):
        return (V_VULNERABLE_EOL,
                f"PHP {major}.{minor} is end-of-life; no PHP2Shell fix exists.")

    if branch in NO_UPSTREAM_FIX:
        return (V_VULNERABLE_NO_UPSTREAM,
                f"PHP {major}.{minor} is affected and has no mainline fix; "
                f"a distro backport or upgrade is required.")

    if branch in FIXED_PATCH:
        fixed_at = FIXED_PATCH[branch]
        if patch is None:
            return (V_UNKNOWN_PATCH,
                    f"PHP {major}.{minor} is an affected branch, but the patch "
                    f"level is unknown. Vulnerable below {major}.{minor}.{fixed_at}; "
                    f"confirm the exact build serving requests.")
        if patch < fixed_at:
            return (V_VULNERABLE,
                    f"PHP {major}.{minor}.{patch} is below the fixed release "
                    f"{major}.{minor}.{fixed_at}.")
        return (V_FIXED,
                f"PHP {major}.{minor}.{patch} is at or above the fixed release "
                f"{major}.{minor}.{fixed_at}. (Note: distro backports may keep "
                f"an older number — verify the package changelog.)")

    # Branches newer than anything we know about (e.g. 8.6+, 9.x).
    if major > 8 or (major == 8 and minor > 5):
        return (V_UNKNOWN,
                f"PHP {major}.{minor} is newer than this tool's data "
                f"(released {', '.join(CVES)} era). Assume fixed only if "
                f"released after Oct 2026; verify against the advisory.")

    return (V_UNKNOWN, f"Could not classify PHP {major}.{minor}.")


def verdict_severity(verdict: str, *, serving_web: bool = True) -> str:
    """Map a verdict to a severity. serving_web=True for live/pinned runtime."""
    if verdict == V_VULNERABLE:
        return "CRITICAL" if serving_web else "HIGH"
    if verdict in (V_VULNERABLE_EOL, V_VULNERABLE_NO_UPSTREAM):
        return "HIGH"
    if verdict == V_UNKNOWN_PATCH:
        return "MEDIUM"
    if verdict == V_UNKNOWN:
        return "LOW"
    if verdict == V_FIXED:
        return "INFO"
    return "LOW"


def remediation_for(verdict: str) -> List[str]:
    if verdict == V_VULNERABLE:
        return [REMEDIATION["patch"]]
    if verdict == V_VULNERABLE_EOL:
        return [REMEDIATION["eol"]]
    if verdict == V_VULNERABLE_NO_UPSTREAM:
        return [REMEDIATION["no_upstream"]]
    if verdict == V_UNKNOWN_PATCH:
        return ["Confirm the exact PHP build serving web requests (phpinfo / "
                "package manager), then " + REMEDIATION["patch"]]
    if verdict == V_FIXED:
        return ["No action for the engine version; keep workers restarted "
                "after the upgrade and verify config hardening."]
    return ["Manually verify the PHP version against the advisory."]


# ---------------------------------------------------------------------------
# Codebase / repo scanner  (Task 2)
# ---------------------------------------------------------------------------

# Files we inspect for a pinned PHP runtime version.
_DOCKERFILE_NAMES = ("dockerfile",)
_VERSION_PIN_FILES = (".php-version", ".tool-versions")
_CONFIG_EXTS = (".ini",)
_CONFIG_NAMES = ("php.ini", ".user.ini")
_FPM_HINT = re.compile(r"(php-?fpm|fpm\.d|pool\.d)", re.I)

# Dirs we never descend into.
_SKIP_DIRS = {".git", "node_modules", "vendor", ".svn", "__pycache__",
              ".idea", ".vscode", "dist", "build"}

_FROM_RE = re.compile(r"^\s*FROM\s+(\S+)", re.I | re.M)
_ARGENV_RE = re.compile(r"^\s*(?:ARG|ENV)\s+(.+)$", re.I | re.M)
_RUN_RE = re.compile(r"^\s*RUN\s+(.+?)(?=^\s*[A-Z]{3,}\s|\Z)",
                     re.I | re.M | re.S)
# distro PHP package, e.g. php8.1-fpm / php8.3-cli / php7.4
_APT_PHP_RE = re.compile(r"\bphp(\d+)\.(\d+)\b", re.I)
_INSTALL_CTX_RE = re.compile(r"\b(apt-get|apt|apk|yum|dnf|zypper)\b.*\binstall",
                             re.I | re.S)
_COMPOSER_PHP_RE = re.compile(r'"php"\s*:\s*"([^"]+)"')
_GHA_PHP_RE = re.compile(r"php-version\s*:\s*['\"]?([0-9][0-9.]*)", re.I)
_IMAGE_PHP_RE = re.compile(r"image\s*:\s*(\S*php\S*)", re.I)

# php.ini risk patterns: (regex, key, risky_if_fn, remediation_key, note)
_UPLOAD_PROG_RE = re.compile(
    r"^\s*session\.upload_progress\.enabled\s*=\s*(\S+)", re.I | re.M)
_FATAL_BT_RE = re.compile(
    r"^\s*fatal_error_backtraces\s*=\s*(\S+)", re.I | re.M)
_MEM_LIMIT_RE = re.compile(r"^\s*memory_limit\s*=\s*(\S+)", re.I | re.M)
_POST_MAX_RE = re.compile(r"^\s*post_max_size\s*=\s*(\S+)", re.I | re.M)


def _is_truthy_ini(val: str) -> bool:
    return val.strip().strip('"').lower() in ("1", "on", "true", "yes")


def _read_text(path: str, limit: int = 2_000_000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except (OSError, UnicodeError):
        return ""


def _scan_version_string(raw: str, target: str, source_desc: str,
                         findings: List[Finding]) -> None:
    """Classify a version string found in a pin and append a finding."""
    ver = parse_php_version(raw)
    if not ver:
        return
    verdict, explain = classify_version(ver)
    sev = verdict_severity(verdict, serving_web=True)
    vstr = ".".join(str(x) for x in ver if x is not None)
    findings.append(Finding(
        severity=sev,
        title=f"Pinned PHP runtime ({source_desc})",
        target=target,
        detail=explain,
        evidence=raw.strip()[:200],
        php_version=vstr,
        verdict=verdict,
        remediation=remediation_for(verdict),
    ))


def _dockerfile_vars(text: str) -> Dict[str, str]:
    """Collect ARG/ENV default values for later ${VAR} substitution."""
    out: Dict[str, str] = {}
    for m in _ARGENV_RE.finditer(text):
        rest = m.group(1).strip()
        if "=" in rest:
            # one or more KEY=VALUE pairs on the line
            for pair in rest.split():
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    out[k.strip()] = v.strip().strip("\"'")
        else:
            # ENV KEY VALUE  (space form)
            parts = rest.split(None, 1)
            if len(parts) == 2:
                out[parts[0].strip()] = parts[1].strip().strip("\"'")
    return out


def _subst_vars(s: str, variables: Dict[str, str]) -> str:
    def repl(m):
        key = m.group(1) or m.group(2)
        return variables.get(key, m.group(0))
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)",
                  repl, s)


def _scan_dockerfile(path: str, text: str, findings: List[Finding]) -> None:
    variables = _dockerfile_vars(text)

    # --- FROM lines (with ARG/ENV resolution) ---
    for m in _FROM_RE.finditer(text):
        raw = m.group(1)
        img = _subst_vars(raw, variables)
        if "php" not in img.lower():
            continue
        label = f"Dockerfile base image '{img}'"
        if img != raw:
            label += f" (resolved from '{raw}')"
        _scan_version_string(img, path, label, findings)
        if re.search(r"apache", img, re.I):
            findings.append(Finding(
                severity="MEDIUM",
                title="mod_php (Apache) base image",
                target=path,
                detail="Apache mod_php is the highest-risk SAPI for PHP2Shell.",
                evidence=img,
                remediation=[REMEDIATION["mod_php"]],
            ))

    # --- distro PHP packages installed via RUN apt-get/apk/yum/dnf ---
    seen: set = set()
    for rm in _RUN_RE.finditer(text):
        block = rm.group(1)
        # collapse line continuations so multi-line RUN reads as one command
        cmd = block.replace("\\\n", " ").replace("\\\r\n", " ")
        if not _INSTALL_CTX_RE.search(cmd):
            continue
        for pm in _APT_PHP_RE.finditer(cmd):
            major, minor = int(pm.group(1)), int(pm.group(2))
            if major not in (5, 7, 8, 9):
                continue
            if (major, minor) in seen:
                continue
            seen.add((major, minor))
            verdict, explain = classify_version((major, minor, None))
            findings.append(Finding(
                severity=verdict_severity(verdict, serving_web=True),
                title=f"Distro PHP package (php{major}.{minor})",
                target=path,
                detail="Installed via a package manager. " + explain,
                evidence=pm.group(0),
                php_version=f"{major}.{minor}",
                verdict=verdict,
                remediation=remediation_for(verdict),
            ))


def scan_file(path: str, findings: List[Finding]) -> None:
    name = os.path.basename(path).lower()
    text = _read_text(path)
    if not text:
        return

    # --- Dockerfiles: FROM php:... + ARG/ENV + apt-get installs ---
    if name in _DOCKERFILE_NAMES or name.startswith("dockerfile"):
        _scan_dockerfile(path, text, findings)

    # --- composer.json platform/require php ---
    if name == "composer.json":
        for m in _COMPOSER_PHP_RE.finditer(text):
            constraint = m.group(1)
            # constraints like ">=8.3", "^8.2", "8.3.*"
            _scan_version_string(constraint, path,
                                 f"composer.json php constraint '{constraint}'",
                                 findings)

    # --- GitHub Actions / CI php-version ---
    if name.endswith((".yml", ".yaml")):
        for m in _GHA_PHP_RE.finditer(text):
            _scan_version_string(m.group(1), path,
                                 f"CI php-version '{m.group(1)}'", findings)
        for m in _IMAGE_PHP_RE.finditer(text):
            _scan_version_string(m.group(1), path,
                                 f"CI image '{m.group(1)}'", findings)

    # --- .php-version / .tool-versions ---
    if name in _VERSION_PIN_FILES:
        for line in text.splitlines():
            if name == ".tool-versions" and not line.lower().startswith("php"):
                continue
            _scan_version_string(line, path, f"{name} pin", findings)

    # --- php.ini / .user.ini / FPM pool config ---
    looks_like_ini = (name in _CONFIG_NAMES or name.endswith(_CONFIG_EXTS)
                      or _FPM_HINT.search(path))
    if looks_like_ini:
        _scan_ini_config(path, text, findings)


def _scan_ini_config(path: str, text: str, findings: List[Finding]) -> None:
    # session.upload_progress.enabled — default ON, confirmed 109619 path.
    up = _UPLOAD_PROG_RE.search(text)
    if up is None:
        findings.append(Finding(
            severity="MEDIUM",
            title="session.upload_progress not disabled",
            target=path,
            detail="session.upload_progress.enabled is not set here; it "
                   "defaults to On, a confirmed CVE-2026-109619 path.",
            evidence="(setting absent — default On)",
            remediation=[REMEDIATION["upload_progress"]],
        ))
    elif _is_truthy_ini(up.group(1)):
        findings.append(Finding(
            severity="MEDIUM",
            title="session.upload_progress enabled",
            target=path,
            detail="session.upload_progress.enabled is On — a confirmed "
                   "CVE-2026-109619 path.",
            evidence=up.group(0).strip(),
            remediation=[REMEDIATION["upload_progress"]],
        ))

    # fatal_error_backtraces (8.5) — risky if On.
    fb = _FATAL_BT_RE.search(text)
    if fb and _is_truthy_ini(fb.group(1)):
        findings.append(Finding(
            severity="LOW",
            title="fatal_error_backtraces enabled (PHP 8.5)",
            target=path,
            detail="A confirmed mod_php path on PHP 8.5.",
            evidence=fb.group(0).strip(),
            remediation=[REMEDIATION["fatal_backtraces"]],
        ))

    # memory_limit = -1
    ml = _MEM_LIMIT_RE.search(text)
    if ml and ml.group(1).strip() == "-1":
        findings.append(Finding(
            severity="LOW",
            title="Unbounded memory_limit",
            target=path,
            detail="memory_limit=-1 removes the per-request cap and raises "
                   "resource-exhaustion risk.",
            evidence=ml.group(0).strip(),
            remediation=[REMEDIATION["request_limits"]],
        ))

    # Large post_max_size (>32M) when not clearly needed — informational.
    pm = _POST_MAX_RE.search(text)
    if pm:
        val = pm.group(1).strip().upper()
        mb = _ini_size_to_mb(val)
        if mb is not None and mb > 32:
            findings.append(Finding(
                severity="LOW",
                title="Large post_max_size",
                target=path,
                detail=f"post_max_size={val} widens the multipart attack "
                       f"surface for CVE-2026-109618.",
                evidence=pm.group(0).strip(),
                remediation=[REMEDIATION["request_limits"]],
            ))


def _ini_size_to_mb(val: str) -> Optional[float]:
    m = re.match(r"(\d+)\s*([KMG]?)", val.upper())
    if not m:
        return None
    n = int(m.group(1))
    unit = m.group(2)
    return {"": n / 1_048_576, "K": n / 1024, "M": n, "G": n * 1024}[unit]


def scan_codebase(root: str) -> List[Finding]:
    findings: List[Finding] = []
    if not os.path.exists(root):
        raise FileNotFoundError(root)
    if os.path.isfile(root):
        scan_file(root, findings)
        return findings
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            scan_file(os.path.join(dirpath, fn), findings)
    if not findings:
        findings.append(Finding(
            severity="INFO",
            title="No PHP runtime pin or risky config found",
            target=root,
            detail="No Dockerfile/composer/CI PHP version pin or php.ini risk "
                   "setting was detected. This does not prove the deployed "
                   "runtime is safe — verify the version serving requests in "
                   "production.",
        ))
    return findings


# ---------------------------------------------------------------------------
# Live host + fleet modes  (Task 3)  — NON-INTRUSIVE
# ---------------------------------------------------------------------------

_HTTP_TIMEOUT = 8
_USER_AGENT = f"php2shell_audit/{__version__} (defensive-detector; non-intrusive)"


def _http_head_get(url: str, insecure: bool = False
                   ) -> Tuple[Optional[int], Dict[str, str], str]:
    """Fetch a URL non-intrusively. Returns (status, headers, body_snippet).

    Only a plain GET of the given URL is performed. No payloads, no POST,
    no exploit traffic.
    """
    ctx = None
    if url.startswith("https"):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT},
                                 method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT,
                                    context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(65536).decode("utf-8", errors="replace")
            return resp.status, headers, body
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        return e.code, headers, ""
    except (urllib.error.URLError, ssl.SSLError, OSError, ValueError) as e:
        return None, {"_error": str(e)}, ""


_PHPINFO_VER_RE = re.compile(r"PHP Version\s*</?\w*>?\s*([0-9][0-9.]+)")


def scan_host(target: str, *, phpinfo_path: Optional[str] = None,
              insecure: bool = False) -> List[Finding]:
    """Non-intrusive version fingerprint of a single host.

    `target` may be a bare host, host:port, or full URL.
    """
    findings: List[Finding] = []

    if not re.match(r"^https?://", target):
        url = "http://" + target
    else:
        url = target

    status, headers, body = _http_head_get(url, insecure=insecure)
    if status is None:
        findings.append(Finding(
            severity="INFO",
            title="Host unreachable",
            target=target,
            detail=f"Could not connect: {headers.get('_error', 'unknown')}",
        ))
        return findings

    # Collect version candidates from headers.
    candidates: List[Tuple[str, str]] = []  # (source, raw)
    for h in ("x-powered-by", "server"):
        if h in headers and "php" in headers[h].lower():
            candidates.append((h, headers[h]))

    # Optional phpinfo page (only if the operator explicitly points at one).
    if phpinfo_path:
        pi_url = url.rstrip("/") + "/" + phpinfo_path.lstrip("/")
        _, _, pi_body = _http_head_get(pi_url, insecure=insecure)
        m = _PHPINFO_VER_RE.search(pi_body)
        if m:
            candidates.append(("phpinfo", "PHP " + m.group(1)))

    if not candidates:
        findings.append(Finding(
            severity="LOW",
            title="PHP version not disclosed",
            target=target,
            detail="No PHP version in Server/X-Powered-By headers. The server "
                   "may hide it (good practice) — this is NOT an all-clear. "
                   "Confirm the version via authenticated inventory / "
                   "package manager.",
            evidence="; ".join(f"{k}: {v}" for k, v in headers.items()
                               if k in ("server", "x-powered-by")) or "(none)",
        ))
        return findings

    for source, raw in candidates:
        ver = parse_php_version(raw)
        if not ver:
            continue
        verdict, explain = classify_version(ver)
        sev = verdict_severity(verdict, serving_web=True)
        vstr = ".".join(str(x) for x in ver if x is not None)
        findings.append(Finding(
            severity=sev,
            title=f"Live PHP version via {source}",
            target=target,
            detail=explain,
            evidence=f"{source}: {raw}",
            php_version=vstr,
            verdict=verdict,
            remediation=remediation_for(verdict),
        ))
    return findings


def _iter_hosts_from_file(path: str) -> List[str]:
    hosts: List[str] = []
    text = _read_text(path)
    if path.lower().endswith(".csv"):
        reader = csv.reader(text.splitlines())
        for row in reader:
            if row and row[0].strip() and not row[0].strip().startswith("#"):
                hosts.append(row[0].strip())
    else:
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line)
    return hosts


def scan_fleet(list_path: str, *, phpinfo_path: Optional[str] = None,
               insecure: bool = False) -> List[Finding]:
    hosts = _iter_hosts_from_file(list_path)
    all_findings: List[Finding] = []
    for host in hosts:
        all_findings.extend(
            scan_host(host, phpinfo_path=phpinfo_path, insecure=insecure))
    return all_findings


# ---------------------------------------------------------------------------
# Reporting  (Task 4)
# ---------------------------------------------------------------------------


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: SEV_ORDER.get(f.severity, 0),
                  reverse=True)


def render_json(findings: List[Finding], mode: str, target: str) -> str:
    worst = max((SEV_ORDER.get(f.severity, 0) for f in findings), default=0)
    worst_label = next((k for k, v in SEV_ORDER.items() if v == worst), "INFO")
    payload = {
        "tool": "php2shell_audit",
        "version": __version__,
        "cves": CVES,
        "mode": mode,
        "target": target,
        "overall_severity": worst_label,
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    return json.dumps(payload, indent=2)


_SEV_MARK = {
    "CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED ]",
    "LOW": "[LOW ]", "INFO": "[INFO]",
}


def render_text(findings: List[Finding], mode: str, target: str) -> str:
    lines: List[str] = []
    lines.append("=" * 70)
    lines.append(f" PHP2Shell scan  ({', '.join(CVES)})")
    lines.append(f" mode={mode}  target={target}")
    lines.append("=" * 70)

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "  ".join(f"{k}:{counts.get(k,0)}"
                        for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    lines.append(f" Summary: {summary}")
    lines.append("")

    for f in sort_findings(findings):
        lines.append(f"{_SEV_MARK.get(f.severity,'[    ]')} {f.title}")
        lines.append(f"       target : {f.target}")
        if f.php_version:
            lines.append(f"       version: {f.php_version}  "
                         f"({f.verdict})")
        lines.append(f"       detail : {f.detail}")
        if f.evidence:
            lines.append(f"       evidence: {f.evidence}")
        for r in f.remediation:
            lines.append(f"       fix    : {r}")
        lines.append("")

    lines.append("-" * 70)
    lines.append(" NOTE: Version/config detection is non-intrusive and does "
                 "not prove")
    lines.append("       exploitability by exploiting. A hidden version is not "
                 "an all-clear.")
    lines.append(f" {AUTH_NOTICE}")
    lines.append("-" * 70)
    return "\n".join(lines)


def worst_severity_exit(findings: List[Finding]) -> int:
    """Exit code: 0 clean/info, 1 low/med, 2 high/crit — handy for CI gating."""
    worst = max((SEV_ORDER.get(f.severity, 0) for f in findings), default=0)
    if worst >= SEV_ORDER["HIGH"]:
        return 2
    if worst >= SEV_ORDER["LOW"]:
        return 1
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="php2shell_audit.py",
        description="Non-intrusive detector for PHP2Shell "
                    "(CVE-2026-109618 / CVE-2026-109619).",
        epilog=AUTH_NOTICE,
    )
    p.add_argument("--version", action="version",
                   version=f"php2shell_audit {__version__}")
    sub = p.add_subparsers(dest="mode", required=True)

    c = sub.add_parser("codebase", help="Static scan of a repo/directory "
                                        "(offline, always safe).")
    c.add_argument("path", help="Directory or file to scan.")

    h = sub.add_parser("host", help="Non-intrusive version check of ONE "
                                    "authorized host.")
    h.add_argument("target", help="host, host:port, or URL.")
    h.add_argument("--phpinfo", metavar="PATH",
                   help="Optional path to a phpinfo page, e.g. /info.php")
    h.add_argument("--insecure", action="store_true",
                   help="Skip TLS verification (lab use).")
    h.add_argument("--authorized", action="store_true",
                   help="Required: confirm you are authorized to scan this "
                        "host.")

    fl = sub.add_parser("fleet", help="Non-intrusive check over a list/CSV of "
                                      "authorized hosts.")
    fl.add_argument("list", help="Text file (one host/line) or CSV "
                                 "(host in column 1).")
    fl.add_argument("--phpinfo", metavar="PATH",
                    help="Optional phpinfo path to try on each host.")
    fl.add_argument("--insecure", action="store_true",
                    help="Skip TLS verification (lab use).")
    fl.add_argument("--authorized", action="store_true",
                    help="Required: confirm you are authorized to scan these "
                         "hosts.")

    for parser in (c, h, fl):
        parser.add_argument("--json", action="store_true",
                            help="Emit JSON instead of text.")
        parser.add_argument("-o", "--output", metavar="FILE",
                            help="Write report to FILE.")
    return p


def _require_authorization(ns: argparse.Namespace) -> None:
    if getattr(ns, "authorized", False):
        return
    sys.stderr.write(
        "\nRefusing to run a network scan without --authorized.\n"
        f"{AUTH_NOTICE}\n"
        "Re-run with --authorized to confirm you own or are permitted to "
        "assess the target(s).\n\n")
    sys.exit(3)


def main(argv: Optional[List[str]] = None) -> int:
    ns = build_parser().parse_args(argv)

    if ns.mode == "codebase":
        findings = scan_codebase(ns.path)
        target = ns.path
    elif ns.mode == "host":
        _require_authorization(ns)
        findings = scan_host(ns.target, phpinfo_path=ns.phpinfo,
                             insecure=ns.insecure)
        target = ns.target
    elif ns.mode == "fleet":
        _require_authorization(ns)
        findings = scan_fleet(ns.list, phpinfo_path=ns.phpinfo,
                              insecure=ns.insecure)
        target = ns.list
    else:  # pragma: no cover
        return 3

    report = (render_json(findings, ns.mode, target) if ns.json
              else render_text(findings, ns.mode, target))

    if ns.output:
        with open(ns.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        sys.stderr.write(f"Report written to {ns.output}\n")
    else:
        print(report)

    return worst_severity_exit(findings)


if __name__ == "__main__":
    sys.exit(main())

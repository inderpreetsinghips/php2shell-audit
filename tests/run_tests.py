#!/usr/bin/env python3
"""Self-contained test suite for php2shell_audit (no pytest, no deps).

Run:  python3 tests/run_tests.py
Exits non-zero on any failure (suitable for CI).
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import php2shell_audit as s  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")

_failures = []


def check(name, cond):
    print(f"  {'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        _failures.append(name)


# --- version engine --------------------------------------------------------
VERSION_CASES = [
    ("8.3.12", s.V_VULNERABLE),
    ("8.3.36", s.V_FIXED),
    ("8.2.34", s.V_VULNERABLE),
    ("8.2.35", s.V_FIXED),
    ("8.4.26", s.V_VULNERABLE),
    ("8.4.27", s.V_FIXED),
    ("8.5.11", s.V_VULNERABLE),
    ("8.5.12", s.V_FIXED),
    ("8.1.20", s.V_VULNERABLE_NO_UPSTREAM),
    ("8.0.3", s.V_VULNERABLE_NO_UPSTREAM),
    ("7.4.33", s.V_VULNERABLE_NO_UPSTREAM),
    ("7.3.5", s.V_VULNERABLE_EOL),
    ("5.6.40", s.V_VULNERABLE_EOL),
    ("8.3", s.V_UNKNOWN_PATCH),
    ("8.6.0", s.V_UNKNOWN),
]
print("version engine:")
for raw, expect in VERSION_CASES:
    ver = s.parse_php_version(raw)
    verdict, _ = s.classify_version(ver)
    check(f"{raw} -> {expect}", verdict == expect)

print("version parsing:")
check("PHP/8.3.12", s.parse_php_version("PHP/8.3.12") == (8, 3, 12))
check("php:8.4.2-fpm-alpine",
      s.parse_php_version("php:8.4.2-fpm-alpine") == (8, 4, 2))
check("^8.2 (no patch)", s.parse_php_version("^8.2") == (8, 2, None))
check("no version", s.parse_php_version("nginx/1.25") is None)

# --- codebase scanner ------------------------------------------------------
print("codebase scanner:")
findings = s.scan_codebase(FIXTURES)
titles = [f.title for f in findings]
verdicts = {f.php_version: f.verdict for f in findings if f.php_version}

check("flags vulnerable Dockerfile pin as CRITICAL",
      any(f.severity == "CRITICAL" and "8.3.12" == f.php_version
          for f in findings))
check("flags mod_php (Apache) image",
      any("mod_php" in t for t in titles))
check("flags session.upload_progress enabled",
      any("upload_progress" in t for t in titles))
check("flags fixed .php-version as INFO/FIXED",
      verdicts.get("8.3.36") == s.V_FIXED)
check("flags composer branch pin as patch-unknown",
      verdicts.get("8.2") == s.V_UNKNOWN_PATCH)
check("resolves ARG/ENV in FROM (php:${PHP_VERSION} -> 8.2.10 CRITICAL)",
      any(f.php_version == "8.2.10" and f.severity == "CRITICAL"
          and "resolved from" in f.title for f in findings))
check("detects distro package php8.1 via apt-get as HIGH",
      any(f.title.startswith("Distro PHP package")
          and f.php_version == "8.1"
          and f.verdict == s.V_VULNERABLE_NO_UPSTREAM for f in findings))
check("dedupes multiple php8.1-* packages to one finding",
      sum(1 for f in findings if f.title.startswith("Distro PHP package")
          and f.php_version == "8.1") == 1)
check("overall exit code is 2 (high/crit present)",
      s.worst_severity_exit(findings) == 2)

# --- dockerfile unit helpers ----------------------------------------------
print("dockerfile helpers:")
_vars = s._dockerfile_vars("ARG PHP_VERSION=8.3.1\nENV FOO bar\n")
check("ARG default parsed", _vars.get("PHP_VERSION") == "8.3.1")
check("ENV space-form parsed", _vars.get("FOO") == "bar")
check("var substitution",
      s._subst_vars("php:${PHP_VERSION}", _vars) == "php:8.3.1")
check("unknown var left intact",
      s._subst_vars("php:${NOPE}", _vars) == "php:${NOPE}")

# --- reporting -------------------------------------------------------------
print("reporting:")
import json as _json
j = s.render_json(findings, "codebase", FIXTURES)
parsed = _json.loads(j)
check("json has findings", parsed["finding_count"] == len(findings))
check("json overall severity CRITICAL",
      parsed["overall_severity"] == "CRITICAL")
check("text report renders", "PHP2Shell scan" in
      s.render_text(findings, "codebase", FIXTURES))

# --- summary ---------------------------------------------------------------
print()
if _failures:
    print(f"FAILED: {len(_failures)} check(s): {_failures}")
    sys.exit(1)
print("ALL TESTS PASSED")
sys.exit(0)

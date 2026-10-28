# php2shell_audit

A small, dependency-free detector for **PHP2Shell** —
`CVE-2026-109618` (RCE via out-of-memory corruption) and
`CVE-2026-109619` (RCE via stale global state / heap use-after-free).
Both are critical (CVSS 9.2), unauthenticated, and exploited in the wild.

![php2shell_audit demo](docs/demo.svg)

> **What this is:** a *defensive* detector. It tells you **whether a system
> is vulnerable and how exposed it is**, from the PHP version and runtime
> configuration — the same way Qualys/Nessus detect this class of engine bug.
>
> **What this is not:** an exploit. It never sends the memory-corruption
> payload, never attempts code execution, and does no intrusive testing. For
> a version-based engine vulnerability, the version + exposure verdict is the
> reliable signal; you do not need to pop a shell to confirm it.

---

## ⚠️ Authorized use only

Live `host` and `fleet` scanning performs network requests against the
targets you give it. **Only run it against systems you own or have explicit,
written permission to assess.** Unauthorized scanning may be illegal in your
jurisdiction. The `host`/`fleet` modes require an explicit `--authorized`
flag as a deliberate speed bump. `codebase` mode is fully offline and safe to
run anywhere.

---

## Why version + config (and not "vulnerable code")

PHP2Shell lives in the **PHP interpreter**, not in application source. There
is no "vulnerable-looking" line of your PHP to grep for. What matters is:

1. **Which PHP build serves requests** — compared to the fixed releases, and
2. **Runtime configuration** that opens or widens the attack surface.

### Fixed releases

| Branch | Vulnerable below | Status |
|--------|------------------|--------|
| 8.5.x  | 8.5.12           | fixed in 8.5.12 |
| 8.4.x  | 8.4.27           | fixed in 8.4.27 |
| 8.3.x  | 8.3.36           | fixed in 8.3.36 |
| 8.2.x  | 8.2.35           | fixed in 8.2.35 |
| 8.1 / 8.0 / 7.4 | all | **no mainline fix** — distro backport or upgrade |
| 7.3 and older | all | **end of life** — upgrade |

> Patching is not enough by itself: **restart every PHP worker** after
> upgrading, or the running process keeps the vulnerable code. Distro
> backports may keep an old version number — verify the package changelog
> references the CVEs.

### Configuration amplifiers the tool flags
- `session.upload_progress.enabled` (default **On**) — a confirmed
  CVE-2026-109619 path.
- `fatal_error_backtraces` on PHP 8.5 — a confirmed mod_php path.
- `memory_limit = -1`, large `post_max_size`, permissive multipart limits —
  widen the CVE-2026-109618 surface.
- **mod_php (Apache prefork)** base images — the highest-risk SAPI.

---

## Repository layout

```
php2shell-audit/
├── php2shell_audit.py        # the scanner (single file, stdlib only)
├── README.md
├── LICENSE                  # MIT
├── SECURITY.md              # responsible-use notice
├── CONTRIBUTING.md
├── CHANGELOG.md
├── .gitignore
├── .github/workflows/ci.yml # runs tests on Python 3.8–3.12
├── docs/SAMPLE_REPORT.txt   # real example output (proof-of-detection)
├── examples/hosts.txt.example
└── tests/
    ├── run_tests.py         # self-contained suite (no pytest)
    └── fixtures/            # sample repo files the tests scan
```

---

## Install

No installation and no dependencies. Python 3.8+.

```bash
chmod +x php2shell_audit.py
```

## Running the tests

```bash
python3 tests/run_tests.py
```

## Demo

See [`docs/DEMO.md`](docs/DEMO.md) for a walkthrough of both modes with real
output you can reproduce in two minutes using the bundled mock lab:

- **Code scan** — captured output: [`docs/SAMPLE_REPORT.txt`](docs/SAMPLE_REPORT.txt)
- **URL / live-host scan** — captured output: [`docs/SAMPLE_REPORT_HOST.txt`](docs/SAMPLE_REPORT_HOST.txt)

The mock lab (`testlab/`) uses no real PHP and is not exploitable — it exists
so anyone can verify the scanner reports the right verdicts. See
[`testlab/README.md`](testlab/README.md).

---

## Usage

### 1. Codebase / repo scan (offline, always safe)

Walks a repo for a pinned PHP runtime and risky config:

- Dockerfile `FROM php:...` (with `ARG`/`ENV` version resolution)
- distro packages installed via `apt-get`/`apk`/`yum`/`dnf` (e.g. `php8.1-fpm`)
- `composer.json` php constraint, CI `php-version`, `.php-version`,
  `.tool-versions`
- `php.ini` / FPM settings (`session.upload_progress`,
  `fatal_error_backtraces`, memory/request limits)

```bash
python3 php2shell_audit.py codebase /path/to/repo
python3 php2shell_audit.py codebase /path/to/repo --json -o report.json
```

Great as a CI gate — see exit codes below.

### 2. Single live host (authorized)

Non-intrusive: one plain GET, reads `Server` / `X-Powered-By`, optionally a
`phpinfo` page you point it at.

```bash
python3 php2shell_audit.py host staging.example.com --authorized
python3 php2shell_audit.py host https://app.example.com --authorized --phpinfo /info.php
```

### 3. Fleet / inventory (authorized)

Takes a newline list or a CSV (host in column 1) and produces a ranked
exposure report.

```bash
python3 php2shell_audit.py fleet hosts.txt --authorized
python3 php2shell_audit.py fleet assets.csv --authorized --json -o fleet.json
```

### Common flags
- `--json` — machine-readable output.
- `-o FILE` / `--output FILE` — write the report to a file.
- `--insecure` — skip TLS verification (lab use only).

---

## Exit codes (CI-friendly)

| Code | Meaning |
|------|---------|
| `0`  | Clean / informational only |
| `1`  | Low/medium findings |
| `2`  | High/critical findings |
| `3`  | Refused (missing `--authorized`) or usage error |

Example gate:

```bash
python3 php2shell_audit.py codebase . || echo "PHP2Shell exposure found"
```

---

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `VULNERABLE` | Version is below the fixed release for its branch. |
| `VULNERABLE_EOL` | End-of-life branch, no fix — upgrade. |
| `VULNERABLE_NO_UPSTREAM_FIX` | Affected branch with no mainline fix — distro backport/upgrade. |
| `BRANCH_AFFECTED_PATCH_UNKNOWN` | On an affected branch but exact patch unknown — confirm the build. |
| `FIXED` | At/above the fixed release (verify distro backport changelog). |
| `UNKNOWN` | Newer than this tool's data, or unclassifiable. |

---

## Important limits

- **A hidden version is not an all-clear.** Servers that suppress their
  version header get a `LOW` finding, not a pass — confirm via authenticated
  inventory.
- A `composer.json`/CI pin is what the project *declares*, which may differ
  from the build actually serving production traffic. Always confirm the live
  runtime (`phpinfo` / package manager) for the final word.
- This tool detects exposure; it does not and will not prove exploitability
  by exploiting.

---

## Keeping it current

Fixed-version thresholds live in `FIXED_PATCH` / `NO_UPSTREAM_FIX` near the
top of `php2shell_audit.py`. If PHP ships further backports (e.g. for 8.1),
update those two tables.

## References
- PHP security advisories: GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp
- watchTowr, Qualys, Akamai, Arctic Wolf PHP2Shell write-ups (Oct 2026)

## License

MIT. Provided as-is, with no warranty. You are responsible for using it only
against systems you are authorized to assess.

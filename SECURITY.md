# Security & Responsible Use

## This is a detector, not an exploit

`php2shell_audit` determines whether a system is exposed to PHP2Shell
(`CVE-2026-109618`, `CVE-2026-109619`) from its PHP version and runtime
configuration. It is **non-intrusive**: it issues only plain, read-only HTTP
GET requests, never sends the memory-corruption payload, and never attempts
code execution. It will not be extended with weaponized exploitation.

## Authorized use only

The `host` and `fleet` modes make network requests to the targets you supply.
Run them **only** against systems you own or are explicitly authorized to
assess. Unauthorized scanning may violate computer-misuse laws in your
jurisdiction. Both modes require the `--authorized` flag as a deliberate
confirmation step. The `codebase` mode is fully offline.

## Reporting a vulnerability in this tool

If you find a bug or a false negative/positive that affects detection
accuracy, please open an issue (for non-sensitive problems) or contact the
maintainer privately for anything that could be abused. Include the tool
version (`php2shell_audit.py --version`), the input, and the expected vs actual
result.

## Keeping detection current

Fixed-version thresholds are in `FIXED_PATCH` and `NO_UPSTREAM_FIX` at the top
of `php2shell_audit.py`. Update them when PHP ships further releases or
backports, and add a note to `CHANGELOG.md`.

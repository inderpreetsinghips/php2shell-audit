# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [1.1.0] - 2026-10-28
### Added
- Codebase scan now resolves Dockerfile `ARG`/`ENV` variables in `FROM`
  (e.g. `FROM php:${PHP_VERSION}`).
- Codebase scan detects distro PHP packages installed via
  `apt-get`/`apk`/`yum`/`dnf` (e.g. `php8.1-fpm`), deduped per version.
- Tests and fixtures for both new detections.

## [1.0.0] - 2026-10-28
### Added
- Initial release.
- `codebase` mode: offline scan of repos for pinned PHP runtime versions
  (Dockerfile, `composer.json`, CI `php-version`, `.php-version`,
  `.tool-versions`) and risky `php.ini`/FPM config.
- `host` mode: non-intrusive version fingerprint of a single authorized host.
- `fleet` mode: ranked exposure report over a host list or CSV.
- Version engine for CVE-2026-109618 / CVE-2026-109619 with branch-aware
  verdicts (vulnerable / fixed / EOL / no-upstream-fix / patch-unknown).
- Text and JSON reporting; CI-friendly exit codes.
- `--authorized` gate on network modes.
- Self-contained test suite (`tests/run_tests.py`).
- `testlab/`: mock target server (`mock_vuln_target.py`), optional Docker
  compose with real PHP, and a lab guide for validating detection.
- `docs/demo.svg`: looping animated terminal demo for the README.

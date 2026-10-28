# Test lab

Targets for validating `php2shell_audit` detection. **None of these are
exploitable** — they exist only to give the scanner something to fingerprint.

There are three ways to test, from safest to most realistic:

## 1. Codebase mode — no server needed

The repo ships sample files under `tests/fixtures/`:

```bash
python3 php2shell_audit.py codebase tests/fixtures
```

You should see a CRITICAL for the vulnerable Dockerfile pin, MEDIUMs for the
config and branch pins, and an INFO for the fixed `.php-version`.

## 2. Mock targets — pure Python, no PHP, no Docker (recommended)

`mock_vuln_target.py` is a plain HTTP server that *advertises* a PHP version
in its headers. It runs no PHP and cannot be attacked.

Start the 4-target lab in one terminal:

```bash
python3 testlab/mock_vuln_target.py --lab
```

In another terminal:

```bash
python3 php2shell_audit.py fleet testlab/lab_hosts.txt --authorized
python3 php2shell_audit.py host 127.0.0.1:8801 --authorized --phpinfo /info.php
```

Expected verdicts:

| Port | Advertises | Expected |
|------|------------|----------|
| 8801 | PHP 8.3.12 (mod_php) | **CRITICAL** — VULNERABLE |
| 8802 | PHP 8.1.20 | **HIGH** — no upstream fix |
| 8803 | PHP 8.3.36 | **INFO** — FIXED |
| 8804 | (no PHP header) | **LOW** — version not disclosed |

Single custom target:

```bash
python3 testlab/mock_vuln_target.py --port 8801 --php-version 8.5.11 --sapi fpm --phpinfo
```

## 3. Real PHP via Docker (optional, most realistic headers)

Only if you want to confirm against genuine PHP/Apache header output. These
containers run outdated PHP and are bound to `127.0.0.1` — **never expose
them**, and tear them down when finished.

```bash
docker compose -f testlab/docker-compose.yml up -d
python3 php2shell_audit.py host 127.0.0.1:8811 --authorized   # expect CRITICAL
python3 php2shell_audit.py host 127.0.0.1:8812 --authorized   # expect FIXED
docker compose -f testlab/docker-compose.yml down
```

---

**Reminder:** detection is version/config based and non-intrusive. The lab
confirms the scanner *identifies* exposure correctly; it does not and should
not demonstrate exploitation.

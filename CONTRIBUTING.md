# Contributing

Thanks for helping improve PHP2Shell detection.

## Ground rules
- This project stays a **defensive detector**. PRs that add exploitation,
  payload delivery, or intrusive testing will be declined.
- Standard library only — no third-party runtime dependencies.
- Keep Python 3.8 compatibility.

## Running the tests
```bash
python3 tests/run_tests.py
```
All checks must pass. Add a case to `tests/run_tests.py` for any new detection.

## Updating version data
Edit `FIXED_PATCH` / `NO_UPSTREAM_FIX` in `php2shell_audit.py` and note the
change in `CHANGELOG.md`.

## Style
- Clear names, short functions, a docstring per public function.
- Every finding needs a severity, a plain-language detail, and remediation.

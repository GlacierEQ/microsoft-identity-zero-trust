# CI Lint Ratchet

## Purpose

The reusable strict Python CI runs Ruff lint, Ruff format check, compileall,
and pytest across this repository.

On 2026-09-01 the first exact-head CI run for the agent-authorization wave
exposed 72 pre-existing Ruff findings across legacy files that were not changed
by that feature wave.

The repository now uses an explicit baseline instead of either:

- weakening the new code to match legacy style; or
- rewriting unrelated legacy behavior merely to make one feature pass CI.

## Baseline rule

The paths in `pyproject.toml` under `extend-exclude` are the pre-existing
Python lint/format debt set.

New Python files are **not** excluded.

The baseline may shrink as a dedicated cleanup wave verifies each legacy file.
It should not grow merely to make new failures disappear.

## New-code gate

The 2026-09-01 authorization-plane files remain subject to the complete strict
runner sequence:

1. `ruff check .`
2. `ruff format --check .`
3. `python -m compileall -q .`
4. `pytest -x -q`

## Legacy debt inventory

- `.integrity/watchdog_daemon.py`
- `mastermind_sidecar.py`
- `scripts/operate.py`
- `src/promotion_authority.py`
- `src/workload_identity.py`
- `src/zero_trust.py`
- `tests/test_adversarial.py`
- `tests/test_promotion_authority.py`
- `tests/test_workload_identity.py`
- `tests/test_zero_trust.py`

## Exit condition

A file leaves the baseline only after its behavior is preserved by tests and it
passes the current repository lint/format gate.

This is a ratchet, not a permanent exemption.

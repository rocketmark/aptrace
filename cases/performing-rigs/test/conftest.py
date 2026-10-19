"""
Interpreter partition for the Performing Rigs Python tests.

The case tests run in two environments (docs/toolchain.md):

- agent/.venv (Python 3.12, pytest, pydantic; no Unicorn), for tests that
  import aptrace_agent;
- tools/unicorn/.venv (pinned unicorn==2.1.4; no pytest), for the concrete
  harness tests, which are plain-assertion scripts.

The scripts below execute Unicorn. Collected by pytest under an interpreter
without Unicorn, they are reported as skipped with the reason, never run
and never passed. run_python_tests.sh runs every test file under its
declared interpreter.
"""

from __future__ import annotations

import importlib.util

import pytest

UNICORN_SCRIPTS = {"test_concrete.py", "test_feather_m4_profile.py", "test_observe_scenarios.py"}


class _NeedsUnicorn(pytest.Module):
    def collect(self):
        pytest.skip(
            "needs Unicorn (tools/unicorn/requirements.txt), absent from this interpreter; "
            f"run tools/unicorn/.venv/bin/python3 cases/performing-rigs/test/{self.path.name} "
            "or cases/performing-rigs/test/run_python_tests.sh"
        )


def pytest_pycollect_makemodule(module_path, parent):
    if module_path.name in UNICORN_SCRIPTS and importlib.util.find_spec("unicorn") is None:
        return _NeedsUnicorn.from_parent(parent, path=module_path)

    return None

"""Regression coverage for fail-closed HOL Guard hook evaluation."""

import io
import json
import sys

from src.hooks import hol_guard_pretool as guard


def test_unexpected_guard_evaluation_error_exits_with_blocking_code(monkeypatch, capsys):
    """Unknown internal failures must not become hook runner's nonblocking status 1."""
    valid_request = {
        "hook_event": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(valid_request)))

    def fail_unexpectedly(_payload):
        raise RuntimeError("simulated unexpected Guard evaluation failure")

    monkeypatch.setattr(guard, "evaluate", fail_unexpectedly)
    assert guard.main() == guard.BLOCK_EXIT
    assert capsys.readouterr().err.strip() == "guard_error"

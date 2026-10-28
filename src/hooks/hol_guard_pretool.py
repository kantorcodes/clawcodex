from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

BLOCK_EXIT = 2
TIMEOUT_SECONDS = 10.0


def _command_context(payload: Any) -> tuple[str, str | None] | None:
    if not isinstance(payload, dict):
        return None
    if payload.get("hook_event") != "PreToolUse":
        return None
    if payload.get("tool_name") != "Bash":
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    cwd = tool_input.get("cwd")
    if cwd is not None and (not isinstance(cwd, str) or not cwd.strip()):
        return None
    return command, cwd


def _guard_allows(command: str, cwd: str | None = None) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["hol-guard", "command", "test", "--json", "--", command],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
            cwd=cwd,
        )
    except FileNotFoundError:
        return False, "guard_unavailable"
    except subprocess.TimeoutExpired:
        return False, "guard_timeout"
    except UnicodeError:
        return False, "guard_invalid_output"
    except (OSError, ValueError):
        # Invalid argv (for example, a NUL in a command) must not fail open.
        return False, "guard_error"

    if result.returncode != 0:
        return False, "guard_error"

    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return False, "guard_invalid_output"

    if not isinstance(payload, dict):
        return False, "guard_invalid_output"
    classification = payload.get("classification")
    if not isinstance(classification, dict):
        return False, "guard_invalid_output"

    # Command test reports a classification, not Guard's final policy.
    # Do not allow an explicitly stopped response to be overridden by it.
    decision = payload.get("decision")
    if ("continue" in payload and payload["continue"] is not True) or (
        "decision" in payload
        and (not isinstance(decision, str) or decision.strip().lower() != "allow")
    ):
        return False, "guard_block"
    if "policy_action" in payload and payload["policy_action"] not in ("allow", "not_run"):
        return False, "guard_block"
    hook_output = payload.get("hookSpecificOutput")
    if "hookSpecificOutput" in payload and (
        not isinstance(hook_output, dict)
        or hook_output.get("permissionDecision") != "allow"
        or hook_output.get("hookEventName") != "PreToolUse"
    ):
        return False, "guard_block"

    if classification.get("explicitly_benign") is True and payload.get("minimum_action") == "allow":
        return True, "guard_allow"
    return False, "guard_block"


def evaluate(payload: Any) -> tuple[bool, str]:
    context = _command_context(payload)
    if context is None:
        return False, "guard_invalid_input"
    command, cwd = context
    return _guard_allows(command, cwd)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, TypeError, UnicodeError, OSError):
        print("guard_invalid_input", file=sys.stderr)
        return BLOCK_EXIT

    allowed, reason = evaluate(payload)
    if allowed:
        return 0
    print(reason, file=sys.stderr)
    return BLOCK_EXIT


if __name__ == "__main__":
    raise SystemExit(main())

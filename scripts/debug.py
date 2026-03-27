#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Debug helper for the conformance test iteration loop.

Provides quick access to conformance logs, vouch Docker logs,
and structured failure analysis — designed for AI consumption.

Usage:
    # Show failures from the last run with full details
    python3 scripts/debug.py failures

    # Show the conformance log for a specific module (by name or ID)
    python3 scripts/debug.py log oidcc-server
    python3 scripts/debug.py log oidcc-server --verbose

    # Show recent vouch server logs (last N lines)
    python3 scripts/debug.py vouch-logs
    python3 scripts/debug.py vouch-logs --lines 100

    # Show vouch logs filtered by keyword
    python3 scripts/debug.py vouch-logs --grep error

    # Show the status of all modules in the last run
    python3 scripts/debug.py status
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

from conformance import ConformanceClient, ConformanceError, format_module_log

STATE_FILE = Path(__file__).parent.parent / ".last-run.json"


def load_state() -> dict:
    if not STATE_FILE.exists():
        print("No .last-run.json found. Run a test plan first.", file=sys.stderr)
        sys.exit(1)
    return json.loads(STATE_FILE.read_text())


def cmd_failures(args: argparse.Namespace) -> None:
    """Show detailed failure logs from the last run."""
    state = load_state()
    client = ConformanceClient(server=state["conformance_server"])

    failed = [
        r for r in state.get("results", [])
        if r["result"] not in ("PASSED", "WARNING", "REVIEW", "SKIPPED")
    ]

    if not failed:
        print("No failures in last run.")
        return

    print(f"{len(failed)} failure(s) in plan {state['plan_name']}:\n")

    for r in failed:
        module_id = r.get("module_id", "")
        print(f"{'=' * 70}")
        print(f"MODULE: {r['name']}")
        print(f"RESULT: {r['result']}")
        print(f"ID:     {module_id}")
        print(f"{'=' * 70}")

        if not module_id:
            print("  (no module ID — module may not have started)")
            continue

        try:
            entries = client.get_module_log(module_id)
            output = format_module_log(entries, verbose=args.verbose)
            if output:
                print(output)
            else:
                print("  (no actionable details in log)")
        except ConformanceError as e:
            print(f"  (could not fetch log: {e})")
        print()


def cmd_log(args: argparse.Namespace) -> None:
    """Show the conformance log for a specific module."""
    state = load_state()
    client = ConformanceClient(server=state["conformance_server"])

    target = args.module

    # Resolve module name to ID from last run state.
    for r in state.get("results", []):
        if r["name"] == target:
            target = r["module_id"]
            print(f"# Resolved {args.module} -> {target}", file=sys.stderr)
            break

    if not target:
        print(f"Module '{args.module}' not found in last run", file=sys.stderr)
        sys.exit(1)

    try:
        entries = client.get_module_log(target)
    except ConformanceError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    output = format_module_log(entries, verbose=args.verbose)
    print(output)


def cmd_vouch_logs(args: argparse.Namespace) -> None:
    """Show recent vouch server Docker logs."""
    cmd = ["docker", "compose", "logs", "--tail", str(args.lines), "vouch"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout + result.stderr

    if args.grep:
        lines = output.splitlines()
        keyword = args.grep.lower()
        filtered = [l for l in lines if keyword in l.lower()]
        print("\n".join(filtered))
    else:
        print(output)


def cmd_status(args: argparse.Namespace) -> None:
    """Show status of all modules from the last run."""
    state = load_state()

    print(f"Plan: {state['plan_name']}")
    print(f"ID:   {state['plan_id']}")
    print(f"URL:  {state['conformance_server']}/plan-detail.html?plan={state['plan_id']}")
    print()

    passed = failed = other = 0
    for r in state.get("results", []):
        result = r["result"]
        marker = "+" if result in ("PASSED", "WARNING", "REVIEW", "SKIPPED") else "!"
        print(f"  [{marker}] {result:<8} {r['name']:<55} {r.get('module_id', '')}")
        if result == "PASSED":
            passed += 1
        elif result in ("FAILED", "UNKNOWN"):
            failed += 1
        else:
            other += 1

    print(f"\n  {passed} passed, {failed} failed, {other} other")


def main() -> None:
    parser = argparse.ArgumentParser(description="Conformance test debug helper")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all log entries")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("failures", help="Show failure details from last run")
    sub.add_parser("status", help="Show status of all modules from last run")

    log_p = sub.add_parser("log", help="Show log for a specific module")
    log_p.add_argument("module", help="Module name or ID")

    vouch_p = sub.add_parser("vouch-logs", help="Show vouch server Docker logs")
    vouch_p.add_argument("--lines", type=int, default=50, help="Number of log lines")
    vouch_p.add_argument("--grep", help="Filter logs by keyword")

    args = parser.parse_args()

    if args.command == "failures":
        cmd_failures(args)
    elif args.command == "log":
        cmd_log(args)
    elif args.command == "vouch-logs":
        cmd_vouch_logs(args)
    elif args.command == "status":
        cmd_status(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

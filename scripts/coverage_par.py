#!/usr/bin/env python3
"""Coverage report: PAR endpoint scenarios exercised by the conformance suite vs.
existing Rust tests in vouch.

Reads results/*.json (snapshots of .last-run.json) to discover plan/module IDs,
fetches each module's structured log from the conformance suite, extracts every
HTTP exchange against /oauth/par, fingerprints each by (auth method, request
shape, response status, error code), then cross-references the fingerprints
against test function names in
crates/vouch-server/src/handlers/oidc/tests/rfc9126.rs in the vouch repo.

Output: markdown to stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
from collections import defaultdict
from pathlib import Path

from conformance import ConformanceClient


PAR_PATH_RE = re.compile(r"/oauth/par(?:\?|$)")
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
DEFAULT_VOUCH_REPO = Path(
    os.environ.get("VOUCH_REPO_PATH", "../vouch")
).resolve()
PAR_TESTS_REL = Path(
    "crates/vouch-server/src/handlers/oidc/tests/rfc9126.rs"
)


def auth_method(req_entry: dict) -> str:
    """Classify how the PAR request authenticates."""
    headers = req_entry.get("request_headers") or {}
    body = req_entry.get("request_body") or ""
    body_params = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
    has_mtls = bool(req_entry.get("request_mutual_tls"))
    auth_header = next(
        (
            v
            for k, v in headers.items()
            if k.lower() == "authorization"
        ),
        "",
    )

    if has_mtls and "client_assertion" in body_params:
        return "mtls+private_key_jwt"
    if has_mtls:
        return "mtls"
    if auth_header.lower().startswith("basic "):
        return "basic"
    if "client_assertion" in body_params:
        return "private_key_jwt"
    if "client_secret" in body_params:
        return "client_secret_post"
    if "client_id" in body_params:
        return "client_id_only"
    return "none"


def request_shape(req_entry: dict) -> dict[str, bool]:
    """Notable request-shape signals beyond auth."""
    body = req_entry.get("request_body") or ""
    params = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
    return {
        "has_request_jwt": "request" in params,
        "has_request_uri": "request_uri" in params,
        "has_pkce": "code_challenge" in params,
        "pkce_plain": params.get("code_challenge_method") == "plain",
        "has_dpop_header": any(
            k.lower() == "dpop"
            for k in (req_entry.get("request_headers") or {})
        ),
    }


def error_code(resp_entry: dict) -> str:
    body = resp_entry.get("response_body") or ""
    try:
        return json.loads(body).get("error", "")
    except (ValueError, AttributeError):
        return ""


def fingerprint(req: dict, resp: dict) -> tuple:
    """Hashable scenario key."""
    shape = request_shape(req)
    status = (resp.get("response_status_code") or "").split()[0]
    return (
        auth_method(req),
        tuple(sorted(k for k, v in shape.items() if v)),
        status,
        error_code(resp),
    )


def fingerprint_label(fp: tuple) -> str:
    auth, shape_flags, status, err = fp
    flags = ",".join(shape_flags) if shape_flags else "plain"
    err_part = f" error={err}" if err else ""
    return f"auth={auth} | {flags} | {status}{err_part}"


def pair_http_entries(log: list[dict]) -> list[tuple[dict, dict]]:
    """Pair adjacent (request, response) entries on the same src."""
    pairs = []
    pending: dict[str, dict] = {}
    for e in log:
        if e.get("http") == "request":
            pending[e.get("src", "")] = e
        elif e.get("http") == "response":
            req = pending.pop(e.get("src", ""), None)
            if req is not None:
                pairs.append((req, e))
    return pairs


def is_par_call(req_entry: dict) -> bool:
    uri = req_entry.get("request_uri", "")
    return bool(PAR_PATH_RE.search(uri))


def collect_scenarios(
    client: ConformanceClient,
    results: list[Path],
) -> dict[tuple, dict]:
    """Return scenario fingerprint → {modules: [...], example: (req, resp)}."""
    by_fp: dict[tuple, dict] = defaultdict(
        lambda: {"modules": [], "example": None}
    )
    for path in results:
        snap = json.loads(path.read_text())
        plan_name = snap.get("plan_name", path.stem)
        for r in snap.get("results", []):
            mid = r.get("module_id")
            if not mid:
                continue
            try:
                log = client.get_module_log(mid)
            except Exception as exc:  # noqa: BLE001
                print(
                    f"# warn: log fetch failed for {r['name']}: {exc}",
                    file=sys.stderr,
                )
                continue
            for req, resp in pair_http_entries(log):
                if not is_par_call(req):
                    continue
                fp = fingerprint(req, resp)
                by_fp[fp]["modules"].append(f"{plan_name}::{r['name']}")
                if by_fp[fp]["example"] is None:
                    by_fp[fp]["example"] = (req, resp)
    return by_fp


def load_vouch_par_tests(vouch_repo: Path) -> list[str]:
    """Return the list of test function names in rfc9126.rs."""
    path = vouch_repo / PAR_TESTS_REL
    if not path.exists():
        print(f"# warn: {path} not found", file=sys.stderr)
        return []
    src = path.read_text()
    return re.findall(r"async fn (test_\w+)\(", src)


AUTH_KEYWORDS = {
    "basic": ("basic_auth", "basic"),
    "client_secret_post": ("post_body", "client_secret_post", "secret_post"),
    "private_key_jwt": ("private_key_jwt", "client_assertion", "pkjwt"),
    "mtls": ("mtls", "tls_client_auth"),
    "mtls+private_key_jwt": ("mtls", "tls_client_auth"),
    "client_id_only": ("client_id_only", "public_client"),
    "none": ("no_auth", "missing_auth", "requires_client_auth"),
}


def cross_reference(fp: tuple, tests: list[str]) -> list[str]:
    """Heuristic match of fingerprint → existing test names."""
    auth, _, _, err = fp
    keywords = AUTH_KEYWORDS.get(auth, ())
    err_keywords = (err.replace("_", ""),) if err else ()
    hits = []
    for t in tests:
        norm = t.replace("_", "")
        if any(kw.replace("_", "") in norm for kw in keywords):
            hits.append(t)
        elif err_keywords and any(kw in norm for kw in err_keywords if kw):
            hits.append(t)
    return hits


def render_report(
    scenarios: dict[tuple, dict],
    tests: list[str],
) -> str:
    lines = [
        "# PAR endpoint coverage",
        "",
        f"Scenarios seen in conformance logs: **{len(scenarios)}**  ",
        f"Existing Rust tests in `rfc9126.rs`: **{len(tests)}**",
        "",
    ]
    grouped: dict[str, list[tuple]] = defaultdict(list)
    for fp in scenarios:
        grouped[fp[0]].append(fp)
    for auth in sorted(grouped):
        lines.append(f"## Auth: `{auth}`")
        lines.append("")
        for fp in sorted(grouped[auth]):
            data = scenarios[fp]
            modules = sorted(set(data["modules"]))
            hits = cross_reference(fp, tests)
            mark = "[x]" if hits else "[ ]"
            lines.append(f"- {mark} **{fingerprint_label(fp)}**")
            shown = ", ".join(modules[:3])
            if len(modules) > 3:
                shown += f" (+{len(modules) - 3} more)"
            lines.append(f"  - seen in {len(modules)} module(s): {shown}")
            if hits:
                lines.append(f"  - matched tests: {', '.join(hits[:3])}")
            else:
                lines.append("  - matched tests: _none — likely uncovered_")
        lines.append("")
    return "\n".join(lines)


def slug(s: str, maxlen: int = 50) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")
    return s[:maxlen]


def suggest_test_name(fp: tuple) -> str:
    auth, shape_flags, status, err = fp
    parts = ["test_rfc9126_par", auth]
    if shape_flags:
        parts.append("_".join(shape_flags))
    if status == "201":
        parts.append("succeeds")
    elif err:
        parts.append(f"rejects_{err}")
    else:
        parts.append(f"returns_{status}")
    return slug("_".join(parts), maxlen=80)


def example_curl(req: dict) -> str:
    """Render a captured PAR request as a curl-like snippet."""
    uri = req.get("request_uri", "")
    headers = req.get("request_headers") or {}
    body = req.get("request_body") or ""
    mtls = req.get("request_mutual_tls")
    lines = [f"POST {uri}"]
    for k, v in headers.items():
        if k.lower() == "content-length":
            continue
        shown = v if len(v) <= 120 else v[:117] + "..."
        lines.append(f"{k}: {shown}")
    if mtls:
        lines.append("(mTLS client cert presented)")
    lines.append("")
    if body:
        params = urllib.parse.parse_qsl(body, keep_blank_values=True)
        for k, v in params:
            shown = v if len(v) <= 80 else v[:77] + "..."
            lines.append(f"  {k}={shown}")
    return "\n".join(lines)


def example_response(resp: dict) -> str:
    status = resp.get("response_status_code", "")
    body = resp.get("response_body", "")
    try:
        body_pretty = json.dumps(json.loads(body), indent=2)
    except (ValueError, TypeError):
        body_pretty = body[:300]
    return f"HTTP {status}\n{body_pretty}"


def render_handoff(
    scenarios: dict[tuple, dict],
    tests: list[str],
) -> str:
    """Detailed per-scenario handoff for the vouch test-writing agent."""
    lines = [
        "# PAR test coverage handoff",
        "",
        "Source: OpenID conformance suite logs against vouch "
        "(`https://vouch:8443/oauth/par`).  ",
        "Target file: "
        "`crates/vouch-server/src/handlers/oidc/tests/rfc9126.rs`  ",
        "Existing test count: **"
        f"{len(tests)}** · Distinct scenarios captured: "
        f"**{len(scenarios)}**",
        "",
        "Each scenario below shows: a concrete captured request/response, "
        "the conformance modules that exercise it, any existing Rust tests "
        "that look related (keyword match — verify before assuming "
        "coverage), and a suggested test name.",
        "",
        "**Note on the heuristic match**: the `Possibly matched tests` field "
        "is a loose keyword match on test function names. It commonly "
        "produces false positives (e.g. an mTLS-keyword test matches every "
        "mTLS scenario regardless of what the scenario actually tests). "
        "Treat it as a starting hint, not as evidence of coverage.",
        "",
    ]
    grouped: dict[str, list[tuple]] = defaultdict(list)
    for fp in scenarios:
        grouped[fp[0]].append(fp)
    for auth in sorted(grouped):
        lines.append(f"## Auth method: `{auth}`")
        lines.append("")
        for fp in sorted(grouped[auth]):
            data = scenarios[fp]
            req, resp = data["example"]
            modules = sorted(set(data["modules"]))
            hits = cross_reference(fp, tests)
            suggested = suggest_test_name(fp)
            lines.append(f"### {fingerprint_label(fp)}")
            lines.append("")
            lines.append(f"**Suggested test fn**: `{suggested}`")
            lines.append("")
            lines.append("**Request** (captured example):")
            lines.append("```")
            lines.append(example_curl(req))
            lines.append("```")
            lines.append("")
            lines.append("**Expected response**:")
            lines.append("```")
            lines.append(example_response(resp))
            lines.append("```")
            lines.append("")
            lines.append(
                f"**Seen in {len(modules)} conformance module(s)**:"
            )
            for m in modules[:8]:
                lines.append(f"- `{m}`")
            if len(modules) > 8:
                lines.append(f"- _… and {len(modules) - 8} more_")
            lines.append("")
            if hits:
                lines.append(
                    "**Possibly matched existing tests** (heuristic — "
                    "verify):"
                )
                for h in hits[:5]:
                    lines.append(f"- `{h}`")
            else:
                lines.append(
                    "**Possibly matched existing tests**: none — "
                    "likely uncovered."
                )
            lines.append("")
            lines.append("---")
            lines.append("")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--results-dir",
        type=Path,
        default=RESULTS_DIR,
        help="Directory of .last-run.json snapshots",
    )
    ap.add_argument(
        "--vouch-repo",
        type=Path,
        default=DEFAULT_VOUCH_REPO,
        help="Path to vouch source checkout",
    )
    ap.add_argument(
        "--conformance-server",
        default=os.environ.get(
            "CONFORMANCE_SERVER",
            "https://localhost.emobix.co.uk:8443",
        ),
    )
    ap.add_argument(
        "--handoff",
        action="store_true",
        help="Emit detailed per-scenario handoff for the vouch test-writing "
        "agent instead of the short coverage report.",
    )
    args = ap.parse_args()

    result_files = sorted(args.results_dir.glob("*.json"))
    if not result_files:
        print(
            f"No result files in {args.results_dir}",
            file=sys.stderr,
        )
        sys.exit(1)

    client = ConformanceClient(server=args.conformance_server)
    scenarios = collect_scenarios(client, result_files)
    tests = load_vouch_par_tests(args.vouch_repo)
    if args.handoff:
        print(render_handoff(scenarios, tests))
    else:
        print(render_report(scenarios, tests))


if __name__ == "__main__":
    main()

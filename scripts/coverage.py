#!/usr/bin/env python3
"""Coverage report and test-writing handoff for any vouch OIDC endpoint
exercised by the conformance suite.

Reads results/*.json snapshots to discover plan/module IDs, fetches each
module's structured log from the conformance suite, extracts every HTTP
exchange against the selected endpoint(s), fingerprints them by (auth
method, request-shape flags, response status, error code), then
cross-references against existing Rust tests in
crates/vouch-server/src/handlers/oidc/tests/.

Usage:
    coverage.py --endpoint par
    coverage.py --endpoint token --handoff > TOKEN_TEST_HANDOFF.md
    coverage.py --endpoint userinfo,introspect,revoke --handoff > ...
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


RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
DEFAULT_VOUCH_REPO = Path(
    os.environ.get("VOUCH_REPO_PATH", "../vouch")
).resolve()
TESTS_DIR_REL = Path("crates/vouch-server/src/handlers/oidc/tests")


# Endpoint registry: each endpoint declares a path regex, the candidate
# Rust test files where related tests live (vouch organizes by RFC), and
# a fallback suggested-name prefix.
ENDPOINTS: dict[str, dict] = {
    "par": {
        "path_pattern": r"/oauth/par(?:\?|$)",
        "test_files": ["rfc9126.rs", "rfc9101.rs", "rfc9449.rs",
                       "rfc8705.rs", "rfc7636.rs", "fapi2.rs"],
        "primary": "rfc9126",
    },
    "token": {
        "path_pattern": r"/oauth/token(?:\?|$)",
        "test_files": ["rfc6749_token.rs", "rfc7523.rs", "rfc8705.rs",
                       "rfc9449.rs", "rfc7636.rs", "rfc8693.rs",
                       "rfc9700.rs", "fapi2.rs"],
        "primary": "rfc6749_token",
    },
    "authorize": {
        "path_pattern": r"/oauth/authorize(?:\?|$)",
        "test_files": ["rfc6749_authorize.rs", "rfc9101.rs", "rfc7636.rs",
                       "rfc9207.rs", "rfc9126.rs", "fapi2.rs"],
        "primary": "rfc6749_authorize",
    },
    "register": {
        "path_pattern": r"/oauth/register(?:/|\?|$)",
        "test_files": ["rfc7591.rs", "rfc7592.rs", "rfc8705.rs"],
        "primary": "rfc7591",
    },
    "userinfo": {
        "path_pattern": r"/oauth/userinfo(?:\?|$)",
        "test_files": ["oidc_core.rs", "rfc8705.rs", "rfc9449.rs"],
        "primary": "oidc_userinfo",
    },
    "introspect": {
        "path_pattern": r"/oauth/introspect(?:\?|$)",
        "test_files": ["rfc7662.rs", "rfc8705.rs"],
        "primary": "rfc7662",
    },
    "revoke": {
        "path_pattern": r"/oauth/revoke(?:\?|$)",
        "test_files": ["rfc7009.rs"],
        "primary": "rfc7009",
    },
}


# Map a scenario fingerprint to the most-specific RFC file (heuristic).
SHAPE_TO_RFC: list[tuple[str, str]] = [
    ("has_dpop_header", "rfc9449"),
    ("has_request_jwt", "rfc9101"),
    ("pkce_plain", "rfc7636"),
]

AUTH_TO_RFC: dict[str, str] = {
    "mtls": "rfc8705",
    "mtls+private_key_jwt": "rfc8705",
    "private_key_jwt": "rfc7523",
}


def extract_params(req_entry: dict) -> dict[str, str]:
    """Return form-body + URL query params merged into one dict."""
    body = req_entry.get("request_body") or ""
    uri = req_entry.get("request_uri") or ""
    params: dict[str, str] = {}
    if "?" in uri:
        params.update(
            dict(
                urllib.parse.parse_qsl(
                    uri.split("?", 1)[1], keep_blank_values=True
                )
            )
        )
    if body:
        params.update(
            dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
        )
    return params


def auth_method(req_entry: dict) -> str:
    headers = req_entry.get("request_headers") or {}
    body_params = extract_params(req_entry)
    has_mtls = bool(req_entry.get("request_mutual_tls"))
    auth_header = next(
        (v for k, v in headers.items() if k.lower() == "authorization"),
        "",
    )
    if has_mtls and "client_assertion" in body_params:
        return "mtls+private_key_jwt"
    if has_mtls:
        return "mtls"
    if auth_header.lower().startswith("basic "):
        return "basic"
    if auth_header.lower().startswith("bearer "):
        return "bearer"
    if auth_header.lower().startswith("dpop "):
        return "dpop_bound"
    if "client_assertion" in body_params:
        return "private_key_jwt"
    if "client_secret" in body_params:
        return "client_secret_post"
    if "client_id" in body_params:
        return "client_id_only"
    return "none"


def request_shape(req_entry: dict) -> dict[str, bool]:
    params = extract_params(req_entry)
    headers = req_entry.get("request_headers") or {}
    return {
        "has_request_jwt": "request" in params,
        "has_request_uri": "request_uri" in params,
        "has_pkce": "code_challenge" in params,
        "pkce_plain": params.get("code_challenge_method") == "plain",
        "has_dpop_header": any(k.lower() == "dpop" for k in headers),
        "has_grant_type": "grant_type" in params,
    }


def grant_type(req_entry: dict) -> str:
    return extract_params(req_entry).get("grant_type", "")


def error_code(resp_entry: dict) -> str:
    body = resp_entry.get("response_body") or ""
    try:
        return json.loads(body).get("error", "") or ""
    except (ValueError, AttributeError):
        return ""


def fingerprint(req: dict, resp: dict, include_grant: bool) -> tuple:
    shape = request_shape(req)
    raw_status = resp.get("response_status_code") or ""
    status = str(raw_status).split()[0] if raw_status != "" else ""
    flags = tuple(sorted(k for k, v in shape.items() if v))
    gt = grant_type(req) if include_grant else ""
    return (
        auth_method(req),
        gt,
        flags,
        status,
        error_code(resp),
    )


def fingerprint_label(fp: tuple) -> str:
    auth, gt, flags, status, err = fp
    flag_part = ",".join(flags) if flags else "plain"
    gt_part = f" grant={gt}" if gt else ""
    err_part = f" error={err}" if err else ""
    return f"auth={auth}{gt_part} | {flag_part} | {status}{err_part}"


def pair_http_entries(log: list[dict]) -> list[tuple[dict, dict]]:
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


def matches_endpoints(
    req_entry: dict, patterns: list[re.Pattern]
) -> str | None:
    """Return the endpoint name whose path regex matches, or None."""
    uri = req_entry.get("request_uri", "")
    for name, pat in patterns:
        if pat.search(uri):
            return name
    return None


def collect_scenarios(
    client: ConformanceClient,
    results: list[Path],
    endpoint_patterns: list[tuple[str, re.Pattern]],
    include_grant: bool,
) -> dict[str, dict[tuple, dict]]:
    """Return {endpoint_name: {fingerprint: {modules, example}}}."""
    by_ep: dict[str, dict[tuple, dict]] = defaultdict(
        lambda: defaultdict(
            lambda: {"modules": [], "example": None}
        )
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
                ep = matches_endpoints(req, endpoint_patterns)
                if not ep:
                    continue
                fp = fingerprint(req, resp, include_grant=include_grant)
                bucket = by_ep[ep][fp]
                bucket["modules"].append(f"{plan_name}::{r['name']}")
                if bucket["example"] is None:
                    bucket["example"] = (req, resp)
    return by_ep


def load_existing_tests(
    vouch_repo: Path, files: list[str]
) -> dict[str, list[str]]:
    """Return {filename: [test_fn_names]}."""
    out: dict[str, list[str]] = {}
    for fname in files:
        path = vouch_repo / TESTS_DIR_REL / fname
        if not path.exists():
            continue
        src = path.read_text()
        out[fname] = re.findall(r"async fn (test_\w+)\(", src)
    return out


def pick_target_rfc(fp: tuple, endpoint_primary: str) -> str:
    """Heuristic: most-specific RFC for a scenario based on its shape/auth."""
    auth, _gt, flags, _status, _err = fp
    for flag, rfc in SHAPE_TO_RFC:
        if flag in flags:
            return rfc
    if auth in AUTH_TO_RFC:
        return AUTH_TO_RFC[auth]
    return endpoint_primary


def slug(s: str, maxlen: int = 80) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")
    return s[:maxlen]


def suggest_test_name(
    fp: tuple, endpoint: str, endpoint_primary: str
) -> tuple[str, str]:
    """Return (suggested_fn_name, target_rfc_file)."""
    auth, gt, flags, status, err = fp
    rfc = pick_target_rfc(fp, endpoint_primary)
    parts = [f"test_{rfc}_{endpoint}"]
    parts.append(auth)
    if gt:
        parts.append(gt.replace(":", "_").replace("-", "_"))
    if flags:
        parts.append("_".join(flags))
    if status == "201" or status == "200":
        parts.append("succeeds")
    elif err:
        parts.append(f"rejects_{err}")
    else:
        parts.append(f"returns_{status}")
    return slug("_".join(parts)), f"{rfc}.rs"


AUTH_KEYWORDS = {
    "basic": ("basic_auth", "basic"),
    "client_secret_post": ("post_body", "secret_post"),
    "private_key_jwt": ("private_key_jwt", "client_assertion", "pkjwt"),
    "mtls": ("mtls", "tls_client_auth"),
    "mtls+private_key_jwt": ("mtls", "tls_client_auth"),
    "bearer": ("bearer",),
    "dpop_bound": ("dpop_bound", "dpop"),
    "client_id_only": ("public_client", "client_id_only"),
    "none": ("no_auth", "missing_auth", "requires_client_auth"),
}


def cross_reference(
    fp: tuple, tests_by_file: dict[str, list[str]]
) -> list[str]:
    auth, _gt, _flags, _status, err = fp
    keywords = AUTH_KEYWORDS.get(auth, ())
    err_kw = err.replace("_", "") if err else ""
    hits: list[str] = []
    for fname, names in tests_by_file.items():
        for t in names:
            norm = t.replace("_", "")
            if any(kw.replace("_", "") in norm for kw in keywords):
                hits.append(f"{fname}::{t}")
            elif err_kw and err_kw in norm:
                hits.append(f"{fname}::{t}")
    return hits


def render_report(
    scenarios: dict[tuple, dict],
    tests_by_file: dict[str, list[str]],
    endpoint: str,
    endpoint_primary: str,
) -> str:
    total_tests = sum(len(v) for v in tests_by_file.values())
    lines = [
        f"# {endpoint} endpoint coverage",
        "",
        f"Scenarios captured: **{len(scenarios)}**  ",
        f"Candidate Rust test files searched: "
        f"{', '.join(f'`{f}`' for f in tests_by_file)}  ",
        f"Total test fns across those files: **{total_tests}**",
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
            hits = cross_reference(fp, tests_by_file)
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


def example_curl(req: dict) -> str:
    uri = req.get("request_uri", "")
    headers = req.get("request_headers") or {}
    body = req.get("request_body") or ""
    mtls = req.get("request_mutual_tls")
    method = req.get("request_method", "POST")
    lines = [f"{method} {uri}"]
    for k, v in headers.items():
        if k.lower() == "content-length":
            continue
        shown = v if len(v) <= 120 else v[:117] + "..."
        lines.append(f"{k}: {shown}")
    if mtls:
        lines.append("(mTLS client cert presented)")
    lines.append("")
    if body:
        # Render form-encoded params, or pretty JSON if it's JSON.
        ctype = next(
            (v for k, v in headers.items() if k.lower() == "content-type"),
            "",
        )
        if "json" in ctype.lower():
            try:
                lines.append(json.dumps(json.loads(body), indent=2))
            except (ValueError, TypeError):
                lines.append(body[:600])
        else:
            params = urllib.parse.parse_qsl(body, keep_blank_values=True)
            for k, v in params:
                shown = v if len(v) <= 80 else v[:77] + "..."
                lines.append(f"  {k}={shown}")
    return "\n".join(lines)


def example_response(resp: dict) -> str:
    status = str(resp.get("response_status_code", ""))
    body = resp.get("response_body", "") or ""
    try:
        body_pretty = json.dumps(json.loads(body), indent=2)
    except (ValueError, TypeError):
        body_pretty = body[:400]
    return f"HTTP {status}\n{body_pretty}"


def render_handoff(
    scenarios_by_endpoint: dict[str, dict[tuple, dict]],
    tests_by_file: dict[str, list[str]],
) -> str:
    total_scen = sum(len(s) for s in scenarios_by_endpoint.values())
    lines = [
        "# vouch test coverage handoff",
        "",
        "Source: OpenID conformance suite logs against vouch.  ",
        "Target: `crates/vouch-server/src/handlers/oidc/tests/<rfc>.rs`",
        "",
        f"Endpoints: {', '.join('`'+e+'`' for e in scenarios_by_endpoint)}  ",
        f"Distinct scenarios captured: **{total_scen}**",
        "",
        "Each scenario below shows: a captured request/response example, "
        "the conformance modules that exercise it, possibly-matching "
        "existing Rust tests (loose keyword match — verify), a suggested "
        "test fn name, and a target test file.",
        "",
        "**Caveat**: the cross-reference heuristic matches on auth-method "
        "and error-code keywords. It can produce false positives (an "
        "`mtls` test name will match every mTLS scenario). Use it as a "
        "hint, not as proof of coverage.",
        "",
    ]
    for endpoint, scenarios in scenarios_by_endpoint.items():
        primary = ENDPOINTS[endpoint]["primary"]
        lines.append(f"# Endpoint: `{endpoint}`")
        lines.append("")
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
                hits = cross_reference(fp, tests_by_file)
                fn_name, target = suggest_test_name(
                    fp, endpoint, primary
                )
                lines.append(f"### {fingerprint_label(fp)}")
                lines.append("")
                lines.append(f"**Suggested test fn**: `{fn_name}`  ")
                lines.append(f"**Target file**: `{target}`")
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
                        "**Possibly matched existing tests** (verify):"
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
        "--endpoint",
        required=True,
        help=(
            "Comma-separated endpoint names. "
            f"Available: {', '.join(ENDPOINTS)}"
        ),
    )
    ap.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    ap.add_argument("--vouch-repo", type=Path, default=DEFAULT_VOUCH_REPO)
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
        help="Emit detailed per-scenario handoff doc.",
    )
    args = ap.parse_args()

    endpoint_names = [e.strip() for e in args.endpoint.split(",")]
    for name in endpoint_names:
        if name not in ENDPOINTS:
            print(
                f"Unknown endpoint: {name}. Available: "
                f"{', '.join(ENDPOINTS)}",
                file=sys.stderr,
            )
            sys.exit(1)

    patterns = [
        (n, re.compile(ENDPOINTS[n]["path_pattern"]))
        for n in endpoint_names
    ]

    result_files = sorted(args.results_dir.glob("*.json"))
    if not result_files:
        print(f"No results in {args.results_dir}", file=sys.stderr)
        sys.exit(1)

    # Token endpoint scenarios depend on grant_type — include it in fp.
    include_grant = "token" in endpoint_names

    client = ConformanceClient(server=args.conformance_server)
    by_ep = collect_scenarios(
        client, result_files, patterns, include_grant=include_grant
    )

    candidate_files: list[str] = []
    for name in endpoint_names:
        for f in ENDPOINTS[name]["test_files"]:
            if f not in candidate_files:
                candidate_files.append(f)
    tests_by_file = load_existing_tests(args.vouch_repo, candidate_files)

    if args.handoff:
        # Preserve endpoint order for readability.
        ordered = {n: by_ep.get(n, {}) for n in endpoint_names}
        print(render_handoff(ordered, tests_by_file))
    else:
        for name in endpoint_names:
            print(
                render_report(
                    by_ep.get(name, {}),
                    tests_by_file,
                    name,
                    ENDPOINTS[name]["primary"],
                )
            )


if __name__ == "__main__":
    main()

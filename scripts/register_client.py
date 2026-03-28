#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Register OAuth clients with the Vouch server via Dynamic Client Registration.

Reads client_alias and auth method from the plan config JSON, then:
  - client_secret_basic  (OIDC plans)
  - private_key_jwt      (FAPI 2.0 plans — generates an ES256 key pair)

Outputs shell-evaluable exports for CLIENT_ID, CLIENT_SECRET, CLIENT_JWKS.

Usage:
    eval $(python3 register_client.py \
        --plan fapi2-security-profile-final-test-plan \
        --config config/fapi2-security-profile.json \
        --vouch-url http://localhost:3000)
"""

import argparse
import base64
import json
import re
import ssl
import sys
import urllib.request
from pathlib import Path


CONFORMANCE_BASE_URL = "https://localhost.emobix.co.uk:8443"


def b64url(n: int, length: int = 32) -> str:
    return (
        base64.urlsafe_b64encode(n.to_bytes(length, "big"))
        .rstrip(b"=")
        .decode()
    )


def generate_ec_jwk() -> tuple[dict, dict]:
    """Generate an ES256 key pair and return (public_jwks, private_jwks)."""
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP256R1())
    pub = private_key.public_key().public_numbers()
    priv = private_key.private_numbers()

    public_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(pub.x),
        "y": b64url(pub.y),
        "kid": "cert-key-1",
        "use": "sig",
        "alg": "ES256",
    }
    private_jwk = {**public_jwk, "d": b64url(priv.private_value)}

    return {"keys": [public_jwk]}, {"keys": [private_jwk]}


def build_payload(
    client_alias: str,
    public_jwks: dict | None,
    conformance_base_url: str,
    is_second_client: bool = False,
) -> dict:
    callback = (
        f"{conformance_base_url}/test/a/{client_alias}/callback"
    )
    if public_jwks is not None:
        # The conformance suite's happy-flow adds dummy query params
        # to the second client's redirect_uri. Both must be registered.
        redirect_uris = [callback]
        if is_second_client:
            redirect_uris.append(
                f"{callback}?dummy1=lorem&dummy2=ipsum"
            )
        return {
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "private_key_jwt",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid email",
            "jwks": public_jwks,
            "dpop_bound_access_tokens": True,
        }
    return {
        "redirect_uris": [callback],
        "token_endpoint_auth_method": "client_secret_basic",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "openid email",
    }


def post_dcr(vouch_url: str, payload: dict) -> dict:
    url = vouch_url.rstrip("/") + "/oauth/register"
    data = json.dumps(payload).encode()

    # Allow self-signed certs for local testing.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, context=ctx) as resp:
        return json.loads(resp.read())


def shell_export(env: dict[str, str]) -> None:
    """Print shell-evaluable export statements."""
    for k, v in env.items():
        # Shell-safe quoting: single quotes, escape any embedded ones.
        safe = v.replace("'", "'\\''")
        print(f"export {k}='{safe}'")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plan", required=True, help="Conformance test plan name"
    )
    parser.add_argument(
        "--config",
        required=True,
        type=Path,
        help="Path to plan config JSON",
    )
    parser.add_argument(
        "--vouch-url",
        default="http://localhost:3000",
        help="Base URL of the Vouch server (default: http://localhost:3000)",
    )
    parser.add_argument(
        "--conformance-url",
        default=CONFORMANCE_BASE_URL,
        help="Conformance suite base URL for redirect URIs",
    )
    args = parser.parse_args()

    raw = args.config.read_text()
    match = re.search(r'"client_alias"\s*:\s*"([^"]+)"', raw)
    client_alias = match.group(1) if match else None
    if not client_alias:
        print(
            f"ERROR: No client_alias in {args.config}", file=sys.stderr
        )
        sys.exit(1)

    is_fapi2 = "fapi2" in args.plan

    public_jwks = None
    private_jwks = None
    if is_fapi2:
        public_jwks, private_jwks = generate_ec_jwk()
        print("# ES256 key pair generated", file=sys.stderr)

    payload = build_payload(
        client_alias, public_jwks, args.conformance_url
    )
    response = post_dcr(args.vouch_url, payload)
    print(
        f"# DCR response: {json.dumps(response)}", file=sys.stderr
    )

    client_jwks_str = (
        json.dumps(private_jwks, separators=(",", ":"))
        if private_jwks
        else ""
    )

    env = {
        "CLIENT_ID": response["client_id"],
        "CLIENT_SECRET": response.get("client_secret", ""),
        "CLIENT_JWKS": client_jwks_str,
        "CLIENT_REG_TOKEN": response.get(
            "registration_access_token", ""
        ),
    }

    if is_fapi2:
        public_jwks2, private_jwks2 = generate_ec_jwk()
        print(
            "# ES256 key pair generated for client2", file=sys.stderr
        )
        payload2 = build_payload(
            client_alias, public_jwks2, args.conformance_url,
            is_second_client=True,
        )
        response2 = post_dcr(args.vouch_url, payload2)
        print(
            f"# DCR response (client2): {json.dumps(response2)}",
            file=sys.stderr,
        )
        env["CLIENT2_ID"] = response2["client_id"]
        env["CLIENT2_JWKS"] = json.dumps(
            private_jwks2, separators=(",", ":")
        )
        env["CLIENT2_REG_TOKEN"] = response2.get(
            "registration_access_token", ""
        )

    shell_export(env)


if __name__ == "__main__":
    main()

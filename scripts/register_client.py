#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Register OAuth clients with the Vouch server via Dynamic Client Registration.

Reads client_alias and variant from the plan config JSON, then:
  - client_secret_basic  (OIDC plans)
  - private_key_jwt      (FAPI 2.0 plans — generates an ES256 key pair)
  - tls_client_auth      (FAPI 2.0 MTLS plans — generates self-signed cert)

Outputs shell-evaluable exports for CLIENT_ID, CLIENT_SECRET, CLIENT_JWKS,
and optionally MTLS_CERT, MTLS_KEY, TLS_CLIENT_AUTH_SUBJECT_DN for MTLS.

Usage:
    eval $(python3 register_client.py \
        --plan fapi2-security-profile-final-test-plan \
        --config config/fapi2-security-profile.json \
        --vouch-url https://localhost:9443)
"""

import argparse
import base64
import datetime
import json
import os
import re
import ssl
import sys
import urllib.request
from pathlib import Path


CONFORMANCE_BASE_URL = "https://localhost.emobix.co.uk:8443"


def parse_variant(raw: str) -> dict[str, str]:
    """Extract the variant object from raw config JSON.

    The raw config contains template placeholders (e.g. {CLIENT_JWKS})
    that make it invalid JSON, but the variant block is safe to parse.
    """
    match = re.search(
        r'"variant"\s*:\s*(\{[^}]+\})', raw, re.DOTALL
    )
    if not match:
        return {}
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return {}


def generate_self_signed_cert(cn: str) -> tuple[str, str, str]:
    """Generate a self-signed X.509 cert for mTLS.

    Returns (cert_pem, key_pem, subject_dn).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(
            datetime.datetime.now(datetime.UTC)
            + datetime.timedelta(days=365)
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(
        serialization.Encoding.PEM
    ).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    subject_dn = f"CN={cn}"
    return cert_pem, key_pem, subject_dn


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
    client_auth_type: str = "private_key_jwt",
    sender_constrain: str = "dpop",
    subject_dn: str = "",
    fapi_request_method: str = "",
) -> dict:
    callback = (
        f"{conformance_base_url}/test/a/{client_alias}/callback"
    )
    if public_jwks is None:
        # OIDC plans: simple client_secret_basic
        return {
            "redirect_uris": [callback],
            "token_endpoint_auth_method": "client_secret_basic",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid email",
        }

    # FAPI 2.0 plans
    redirect_uris = [callback]
    if is_second_client:
        redirect_uris.append(
            f"{callback}?dummy1=lorem&dummy2=ipsum"
        )

    auth_method = (
        "tls_client_auth"
        if client_auth_type == "mtls"
        else "private_key_jwt"
    )

    payload: dict = {
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": auth_method,
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "openid email",
        "jwks": public_jwks,
    }

    if client_auth_type == "mtls" and subject_dn:
        payload["tls_client_auth_subject_dn"] = subject_dn

    if sender_constrain == "dpop":
        payload["dpop_bound_access_tokens"] = True
    elif sender_constrain == "mtls":
        payload["tls_client_certificate_bound_access_tokens"] = True

    if fapi_request_method == "signed_non_repudiation":
        payload["request_object_signing_alg"] = "ES256"

    return payload


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


SENSITIVE_KEYS = {
    "CLIENT_SECRET", "CLIENT_JWKS", "CLIENT2_JWKS",
    "MTLS_CERT", "MTLS_KEY", "MTLS2_CERT", "MTLS2_KEY",
    "CLIENT_REG_TOKEN", "CLIENT2_REG_TOKEN",
}


def shell_export(env: dict[str, str]) -> None:
    """Export variables via $GITHUB_ENV when in CI, else print shell exports."""
    github_env = os.environ.get("GITHUB_ENV")
    if github_env:
        with open(github_env, "a") as f:
            for k, v in env.items():
                if k in SENSITIVE_KEYS and v:
                    print(f"::add-mask::{v}")
                # Use heredoc delimiter for values with newlines or quotes.
                f.write(f"{k}<<__EOF__\n{v}\n__EOF__\n")
        return
    for k, v in env.items():
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
        default="https://localhost:9443",
        help="Base URL of the Vouch server (default: https://localhost:9443)",
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
    variant = parse_variant(raw)
    client_auth_type = variant.get("client_auth_type", "private_key_jwt")
    sender_constrain = variant.get("sender_constrain", "dpop")
    fapi_request_method = variant.get("fapi_request_method", "")
    needs_mtls = (
        client_auth_type == "mtls" or sender_constrain == "mtls"
    )

    public_jwks = None
    private_jwks = None
    if is_fapi2:
        public_jwks, private_jwks = generate_ec_jwk()
        print("# ES256 key pair generated", file=sys.stderr)

    # Generate mTLS certs when any variant axis requires MTLS.
    cert_pem = ""
    key_pem = ""
    subject_dn = ""
    if is_fapi2 and needs_mtls:
        cert_pem, key_pem, subject_dn = generate_self_signed_cert(
            f"{client_alias}-client1"
        )
        print("# mTLS client cert generated", file=sys.stderr)

    payload = build_payload(
        client_alias,
        public_jwks,
        args.conformance_url,
        client_auth_type=client_auth_type,
        sender_constrain=sender_constrain,
        subject_dn=subject_dn,
        fapi_request_method=fapi_request_method,
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

    env: dict[str, str] = {
        "CLIENT_ID": response["client_id"],
        "CLIENT_SECRET": response.get("client_secret", ""),
        "CLIENT_JWKS": client_jwks_str,
        "CLIENT_REG_TOKEN": response.get(
            "registration_access_token", ""
        ),
    }

    if is_fapi2 and needs_mtls:
        env["MTLS_CERT"] = cert_pem
        env["MTLS_KEY"] = key_pem
        env["TLS_CLIENT_AUTH_SUBJECT_DN"] = subject_dn

    if is_fapi2:
        public_jwks2, private_jwks2 = generate_ec_jwk()
        print(
            "# ES256 key pair generated for client2", file=sys.stderr
        )

        cert_pem2 = ""
        key_pem2 = ""
        subject_dn2 = ""
        if needs_mtls:
            cert_pem2, key_pem2, subject_dn2 = (
                generate_self_signed_cert(
                    f"{client_alias}-client2"
                )
            )
            print(
                "# mTLS client cert generated for client2",
                file=sys.stderr,
            )

        payload2 = build_payload(
            client_alias,
            public_jwks2,
            args.conformance_url,
            is_second_client=True,
            client_auth_type=client_auth_type,
            sender_constrain=sender_constrain,
            subject_dn=subject_dn2,
            fapi_request_method=fapi_request_method,
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

        if needs_mtls:
            env["MTLS2_CERT"] = cert_pem2
            env["MTLS2_KEY"] = key_pem2
            env["TLS_CLIENT_AUTH_SUBJECT_DN2"] = subject_dn2

    shell_export(env)


if __name__ == "__main__":
    main()

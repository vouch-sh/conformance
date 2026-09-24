#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Test CA for tls_client_auth client certificates.

RFC 8705 §2.1 (tls_client_auth) authenticates a client by a validated
certificate chain plus a subject match, so Vouch only accepts a client
certificate that chains to an anchor in VOUCH_MTLS_CLIENT_CA_CERTS. This
module creates that anchor and issues the client certificates
register_client.py hands to the conformance suite.

The CA must exist before Vouch starts, because Vouch reads the bundle at
startup:

    python3 client_ca.py certs    # writes certs/client-ca.{crt,key}
"""

import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_CERT = "client-ca.crt"
CA_KEY = "client-ca.key"


def _validity(days: int) -> tuple[datetime.datetime, datetime.datetime]:
    now = datetime.datetime.now(datetime.UTC)
    return now - datetime.timedelta(minutes=5), now + datetime.timedelta(days=days)


def ensure_client_ca(directory: Path) -> None:
    """Create the CA certificate and key in `directory` unless both exist."""
    cert_path = directory / CA_CERT
    key_path = directory / CA_KEY
    if cert_path.exists() and key_path.exists():
        return

    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Vouch Conformance Client CA"),
        ]
    )
    not_before, not_after = _validity(3650)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Generated {cert_path}", file=sys.stderr)


def issue_client_cert(cn: str, directory: Path) -> tuple[str, str, str]:
    """Issue a client certificate for `cn` signed by the CA in `directory`.

    Returns (cert_pem, key_pem, subject_dn).
    """
    ca_cert = x509.load_pem_x509_certificate((directory / CA_CERT).read_bytes())
    ca_key = serialization.load_pem_private_key(
        (directory / CA_KEY).read_bytes(), password=None
    )
    if not isinstance(ca_key, ec.EllipticCurvePrivateKey):
        raise TypeError(f"{directory / CA_KEY} is not an EC private key")

    key = ec.generate_private_key(ec.SECP256R1())
    not_before, not_after = _validity(365)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem, f"CN={cn}"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <certs-dir>")
    ensure_client_ca(Path(sys.argv[1]))

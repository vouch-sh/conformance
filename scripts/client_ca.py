# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Issue tls_client_auth client certificates from the test client CA.

RFC 8705 §2.1 (tls_client_auth) authenticates a client by a validated
certificate chain plus a subject match, so Vouch only accepts a client
certificate that chains to an anchor in VOUCH_MTLS_CLIENT_CA_CERTS.
`make client-ca` (a dependency of `make certs`) creates that CA in certs/
before Vouch starts; this module signs the client certificates
register_client.py hands to the conformance suite.
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_CERT = "client-ca.crt"
CA_KEY = "client-ca.key"


def issue_client_cert(cn: str, directory: Path) -> tuple[str, str, str]:
    """Issue a client certificate for `cn` signed by the CA in `directory`.

    Returns (cert_pem, key_pem, subject_dn).
    """
    if not (directory / CA_CERT).exists() or not (directory / CA_KEY).exists():
        raise FileNotFoundError(
            f"no client CA in {directory}; run `make client-ca` first"
        )
    ca_cert = x509.load_pem_x509_certificate((directory / CA_CERT).read_bytes())
    ca_key = serialization.load_pem_private_key(
        (directory / CA_KEY).read_bytes(), password=None
    )
    if not isinstance(ca_key, ec.EllipticCurvePrivateKey):
        raise TypeError(f"{directory / CA_KEY} is not an EC private key")

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
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

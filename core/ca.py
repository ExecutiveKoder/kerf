"""
Certificate Authority for TLS interception.

Generates a root CA on first run (stored under ~/.dastday/), then mints
per-host leaf certificates on demand, signed by that CA. The user installs the
root CA into their browser/OS trust store so intercepted HTTPS validates.

This is the same mechanism every intercepting proxy uses. It only works for
traffic whose client trusts this CA, i.e. the operator's own machine. It cannot
be used to intercept anyone else's traffic.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from modules.brand import CA_CN, NAME

CONFIG_DIR = Path(os.environ.get("DASTDAY_HOME", Path.home() / ".dastday"))
CA_CERT_PATH = CONFIG_DIR / "ca-cert.pem"
CA_KEY_PATH = CONFIG_DIR / "ca-key.pem"


class CertificateAuthority:
    """Owns the root CA and a cache of per-host leaf certs."""

    def __init__(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._leaf_cache: dict[str, tuple[bytes, bytes]] = {}
        self._ca_cert, self._ca_key = self._load_or_create_ca()

    # ------------------------------------------------------------------ CA

    def _load_or_create_ca(self):
        if CA_CERT_PATH.exists() and CA_KEY_PATH.exists():
            cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
            key = serialization.load_pem_private_key(
                CA_KEY_PATH.read_bytes(), password=None
            )
            return cert, key
        return self._create_ca()

    def _create_ca(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, CA_CN),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, NAME),
            ]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        CA_KEY_PATH.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        CA_CERT_PATH.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        # Lock down the private key on POSIX systems.
        try:
            os.chmod(CA_KEY_PATH, 0o600)
        except OSError:
            pass
        return cert, key

    @property
    def ca_cert_pem(self) -> bytes:
        return self._ca_cert.public_bytes(serialization.Encoding.PEM)

    # ---------------------------------------------------------------- leaf

    def cert_for_host(self, hostname: str) -> tuple[bytes, bytes]:
        """Return (cert_pem, key_pem) for hostname, minting and caching if needed."""
        with self._lock:
            if hostname in self._leaf_cache:
                return self._leaf_cache[hostname]
            pair = self._mint_leaf(hostname)
            self._leaf_cache[hostname] = pair
            return pair

    def _mint_leaf(self, hostname: str) -> tuple[bytes, bytes]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        now = datetime.datetime.now(datetime.timezone.utc)

        # SAN: IP if the host is an IP literal, otherwise DNS.
        try:
            san = x509.IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            san = x509.DNSName(hostname)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cert_pem, key_pem

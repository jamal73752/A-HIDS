"""
ssl_manager.py - SSL/TLS certificate management for A-HIDS server.

Auto-generates self-signed certificates for development and supports
loading custom certificates from configuration.
"""

import logging
import os
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Default certificate directory and file paths
DEFAULT_CERT_DIR = "certs"
DEFAULT_CERT_FILE = os.path.join(DEFAULT_CERT_DIR, "server.crt")
DEFAULT_KEY_FILE = os.path.join(DEFAULT_CERT_DIR, "server.key")


def certs_exist(cert_path: str, key_path: str) -> bool:
    """
    Check whether certificate and key files both exist.

    Args:
        cert_path: Path to the certificate file.
        key_path:  Path to the private key file.

    Returns:
        True if both files exist, False otherwise.
    """
    return os.path.isfile(cert_path) and os.path.isfile(key_path)


def generate_self_signed_cert(
    cert_path: str = DEFAULT_CERT_FILE,
    key_path: str = DEFAULT_KEY_FILE,
    common_name: str = "localhost",
    days_valid: int = 365,
) -> bool:
    """
    Generate a self-signed SSL certificate and private key.

    Uses the ``cryptography`` library to create an RSA-2048 key pair
    and an X.509 certificate valid for *days_valid* days.
    The certificate and key are written to *cert_path* and *key_path*.

    Args:
        cert_path:   Destination path for the PEM certificate.
        key_path:    Destination path for the PEM private key.
        common_name: CN value for the certificate subject.
        days_valid:  Number of days the certificate remains valid.

    Returns:
        True on success, False if the ``cryptography`` library is not
        installed or certificate generation failed.
    """
    try:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

    except ImportError:
        logger.warning(
            "cryptography library not installed – cannot generate SSL certs. "
            "Install it with: pip install cryptography"
        )
        return False

    try:
        # Ensure the target directory exists
        cert_dir = os.path.dirname(cert_path)
        if cert_dir:
            os.makedirs(cert_dir, exist_ok=True)

        # Generate RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Build certificate subject and issuer (self-signed → same)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Local"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "A-HIDS"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=days_valid))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"), x509.DNSName(common_name)]
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Write private key (PEM, unencrypted)
        with open(key_path, "wb") as fh:
            fh.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Write certificate (PEM)
        with open(cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))

        logger.info(
            "Self-signed certificate generated: cert=%s key=%s (valid %d days)",
            cert_path,
            key_path,
            days_valid,
        )
        return True

    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Failed to generate SSL certificate: %s", exc, exc_info=True)
        return False


def get_ssl_context(
    ssl_enabled: bool,
    cert_path: str = DEFAULT_CERT_FILE,
    key_path: str = DEFAULT_KEY_FILE,
) -> Optional[Tuple[str, str]]:
    """
    Return an SSL context tuple suitable for ``Flask.run(ssl_context=...)``.

    If *ssl_enabled* is False the function returns None.
    If the certificate files do not exist they are auto-generated.

    Args:
        ssl_enabled: Whether HTTPS is enabled in config.
        cert_path:   Path to the PEM certificate.
        key_path:    Path to the PEM private key.

    Returns:
        ``(cert_path, key_path)`` tuple or None.
    """
    if not ssl_enabled:
        return None

    if not certs_exist(cert_path, key_path):
        logger.info("SSL certs not found – auto-generating self-signed certificate…")
        ok = generate_self_signed_cert(cert_path, key_path)
        if not ok:
            logger.warning(
                "Could not generate SSL certificate – falling back to HTTP."
            )
            return None

    return (cert_path, key_path)

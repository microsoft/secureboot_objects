# @file test_secure_boot_default_keys.py
# This file contains unit tests for secure_boot_default_keys.py
##
# Copyright (c) Microsoft Corporation.
#
# SPDX-Licese-Identifier: BSD-2-Clause-Patent
##
"""Unit tests for secure_boot_default_keys.py."""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from secure_boot_default_keys import _convert_pem_to_der, _is_pem_encoded, build_default_keys


def _generate_pem_certificate() -> bytes:
    """Create a small self-signed certificate for PEM conversion tests."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "secureboot-test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def test_pem_certificate_conversion_round_trip() -> None:
    """PEM inputs should convert to DER and be recognized as PEM-encoded data."""
    pem_data = _generate_pem_certificate()

    assert _is_pem_encoded(pem_data)
    der_data = _convert_pem_to_der(pem_data)
    cert = x509.load_der_x509_certificate(der_data)
    assert cert.subject.rfc4514_string() == "CN=secureboot-test"


def test_build_default_keys_accepts_pem_files(tmp_path) -> None:
    """The key builder should accept PEM certificate files in the keystore."""
    cert_path = tmp_path / "test.pem"
    cert_path.write_bytes(_generate_pem_certificate())

    keystore = {
        "Db": {
            "files": [{"path": str(cert_path)}],
        }
    }

    default_keys = build_default_keys(keystore)

    assert ("x64", "Db") in default_keys
    assert default_keys[("x64", "Db")]

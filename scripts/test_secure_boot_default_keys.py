# @file test_secure_boot_default_keys.py
# This file contains unit tests for secure_boot_default_keys.py
##
# Copyright (c) Microsoft Corporation.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit tests for secure_boot_default_keys.py."""

import datetime
import hashlib
import struct
import tempfile
import unittest
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from secure_boot_default_keys import (
    ARCH_MAP,
    X509_TBS_HASH_GUIDS,
    X509_TBS_HASH_V2_GUIDS,
    build_default_keys,
    create_x509_tbs_hash_signature_list,
)


def _test_certificate() -> x509.Certificate:
    """Create a test certificate."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TBS Hash Test")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(key, hashes.SHA256())
    )


class TestX509TbsHashSignatureList(unittest.TestCase):
    """Test X.509 TBSCertificate hash signature list generation."""

    def test_supported_hash_algorithms(self) -> None:
        """Verify each supported V1 X.509 TBS hash signature list."""
        certificate = _test_certificate()
        certificate_der = certificate.public_bytes(Encoding.DER)
        signature_owner = uuid.UUID("6d6c6473-6100-4000-8000-000000000001")

        for hash_algorithm in ("sha256", "sha384", "sha512"):
            with self.subTest(hash_algorithm=hash_algorithm):
                signature_list = create_x509_tbs_hash_signature_list(
                    certificate_der,
                    signature_owner,
                    hash_algorithm,
                )

                signature_type = uuid.UUID(bytes_le=signature_list[:16])
                list_size, header_size, signature_size = struct.unpack_from("<III", signature_list, 16)
                digest_size = hashlib.new(hash_algorithm).digest_size

                self.assertEqual(signature_type, X509_TBS_HASH_GUIDS[hash_algorithm])
                self.assertEqual(list_size, len(signature_list))
                self.assertEqual(header_size, 0)
                self.assertEqual(signature_size, 16 + digest_size + 16)
                self.assertEqual(signature_list[28:44], signature_owner.bytes_le)
                self.assertEqual(
                    signature_list[44 : 44 + digest_size],
                    hashlib.new(
                        hash_algorithm,
                        certificate.tbs_certificate_bytes,
                    ).digest(),
                )
                self.assertEqual(signature_list[-16:], bytes(16))

    def test_supported_v2_hash_algorithms(self) -> None:
        """Verify each supported V2 X.509 TBS hash signature list."""
        certificate = _test_certificate()
        certificate_der = certificate.public_bytes(Encoding.DER)

        for hash_algorithm in ("sha256", "sha384", "sha512"):
            with self.subTest(hash_algorithm=hash_algorithm):
                signature_list = create_x509_tbs_hash_signature_list(
                    certificate_der,
                    None,
                    hash_algorithm,
                    signature_list_version=2,
                )

                signature_type = uuid.UUID(bytes_le=signature_list[:16])
                list_size, header_size, signature_size = struct.unpack_from("<III", signature_list, 16)
                digest = hashlib.new(
                    hash_algorithm,
                    certificate.tbs_certificate_bytes,
                ).digest()

                self.assertEqual(signature_type, X509_TBS_HASH_V2_GUIDS[hash_algorithm])
                self.assertEqual(list_size, len(signature_list))
                self.assertEqual(header_size, 0)
                self.assertEqual(signature_size, len(digest))
                self.assertEqual(signature_list[28:], digest)

    def test_unsupported_hash(self) -> None:
        """Reject unsupported TBS hash algorithms."""
        certificate_der = _test_certificate().public_bytes(Encoding.DER)

        with self.assertRaisesRegex(ValueError, "Unsupported X.509 TBS hash algorithm"):
            create_x509_tbs_hash_signature_list(
                certificate_der,
                uuid.UUID(int=0),
                "sha1",
            )

    def test_build_default_keys_uses_tbs_hash_option(self) -> None:
        """Build a database from a certificate file configured with tbs_hash."""
        certificate_der = _test_certificate().public_bytes(Encoding.DER)
        signature_owner = "6d6c6473-6100-4000-8000-000000000001"

        with tempfile.TemporaryDirectory() as temp_dir:
            certificate_path = Path(temp_dir) / "test.der"
            certificate_path.write_bytes(certificate_der)
            keystore = {
                "DefaultDb": {
                    "files": [
                        {
                            "path": str(certificate_path),
                            "signature_owner": signature_owner,
                            "tbs_hash": "sha512",
                        }
                    ]
                }
            }

            default_keys = build_default_keys(keystore)

        expected = create_x509_tbs_hash_signature_list(
            certificate_der,
            signature_owner,
            "sha512",
        )
        for arch in ARCH_MAP.values():
            self.assertEqual(default_keys[arch, "DefaultDb"], expected)

    def test_build_default_keys_uses_v2_tbs_hash_without_owner(self) -> None:
        """Build a V2 TBS hash database without a signature owner."""
        certificate_der = _test_certificate().public_bytes(Encoding.DER)

        with tempfile.TemporaryDirectory() as temp_dir:
            certificate_path = Path(temp_dir) / "test.der"
            certificate_path.write_bytes(certificate_der)
            keystore = {
                "DefaultDb": {
                    "files": [
                        {
                            "path": str(certificate_path),
                            "tbs_hash": "sha512",
                            "signature_list_version": 2,
                        }
                    ]
                }
            }

            default_keys = build_default_keys(keystore)

        expected = create_x509_tbs_hash_signature_list(
            certificate_der,
            None,
            "sha512",
            signature_list_version=2,
        )
        for arch in ARCH_MAP.values():
            self.assertEqual(default_keys[arch, "DefaultDb"], expected)


if __name__ == "__main__":
    unittest.main()

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
import json
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
    HASH_V2_GUIDS,
    X509_TBS_HASH_GUIDS,
    X509_TBS_HASH_V2_GUIDS,
    X509_V2_GUID,
    build_default_keys,
    create_hash_signature_list,
    create_x509_tbs_hash_signature_list,
)

EXPECTED_HASH_V2_GUIDS = {
    "sha256": uuid.UUID("65325437-ca92-441e-943d-4e003faeda97"),
    "sha384": uuid.UUID("45db3553-f9a6-4026-8e48-eb1e4b07185c"),
    "sha512": uuid.UUID("d2291d97-f066-4abf-9c57-6363e5fd6903"),
    "sm3": uuid.UUID("ee4df27a-deca-4312-a3ae-65f8a1d8f992"),
}

EXPECTED_X509_TBS_HASH_V2_GUIDS = {
    "sha256": uuid.UUID("af4d21cd-7627-4b81-9e96-d4f3bbc3fae9"),
    "sha384": uuid.UUID("78860e15-f2eb-4d16-8156-231518fb7688"),
    "sha512": uuid.UUID("4d46147a-fa79-43a9-8836-00341c708a70"),
    "sm3": uuid.UUID("a3a48dce-8de4-4634-9194-95bf8d7442bc"),
}


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

        for hash_algorithm in ("sha256", "sha384", "sha512", "sm3"):
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

        for hash_algorithm in ("sha256", "sha384", "sha512", "sm3"):
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

                self.assertEqual(
                    X509_TBS_HASH_V2_GUIDS[hash_algorithm], EXPECTED_X509_TBS_HASH_V2_GUIDS[hash_algorithm]
                )
                self.assertEqual(signature_type, EXPECTED_X509_TBS_HASH_V2_GUIDS[hash_algorithm])
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


class TestV2SignatureList(unittest.TestCase):
    """Test the remaining UEFI 2.12 V2 signature list types."""

    def test_supported_v2_hash_algorithms(self) -> None:
        """Verify each V2 raw hash signature list."""
        for hash_algorithm, expected_guid in EXPECTED_HASH_V2_GUIDS.items():
            with self.subTest(hash_algorithm=hash_algorithm):
                digest = hashlib.new(hash_algorithm, b"image").digest()
                signature_list = create_hash_signature_list(
                    [digest],
                    None,
                    hash_algorithm,
                    signature_list_version=2,
                )

                signature_type = uuid.UUID(bytes_le=signature_list[:16])
                list_size, header_size, signature_size = struct.unpack_from("<III", signature_list, 16)

                self.assertEqual(HASH_V2_GUIDS[hash_algorithm], expected_guid)
                self.assertEqual(signature_type, expected_guid)
                self.assertEqual(list_size, len(signature_list))
                self.assertEqual(header_size, 0)
                self.assertEqual(signature_size, len(digest))
                self.assertEqual(signature_list[28:], digest)

    def test_build_default_keys_uses_v2_x509_without_owner(self) -> None:
        """Build a V2 X.509 certificate signature list without an owner."""
        certificate_der = _test_certificate().public_bytes(Encoding.DER)

        with tempfile.TemporaryDirectory() as temp_dir:
            certificate_path = Path(temp_dir) / "test.der"
            certificate_path.write_bytes(certificate_der)
            keystore = {
                "DefaultDb": {
                    "files": [
                        {
                            "path": str(certificate_path),
                            "signature_list_version": 2,
                        }
                    ]
                }
            }

            default_keys = build_default_keys(keystore)

        for signature_list in default_keys.values():
            signature_type = uuid.UUID(bytes_le=signature_list[:16])
            list_size, header_size, signature_size = struct.unpack_from("<III", signature_list, 16)

            self.assertEqual(signature_type, uuid.UUID("79518039-4715-4393-bdf8-d8e3c67fbac7"))
            self.assertEqual(X509_V2_GUID, signature_type)
            self.assertEqual(list_size, len(signature_list))
            self.assertEqual(header_size, 0)
            self.assertEqual(signature_size, len(certificate_der))
            self.assertEqual(signature_list[28:], certificate_der)

    def test_build_default_keys_uses_all_v2_json_hashes_without_owner(self) -> None:
        """Build V2 raw hash lists for every supported JSON hash type."""
        hashes = {
            hash_algorithm: hashlib.new(hash_algorithm, hash_algorithm.encode()).digest()
            for hash_algorithm in EXPECTED_HASH_V2_GUIDS
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = Path(temp_dir) / "hashes.json"
            json_path.write_text(
                json.dumps(
                    {
                        "images": {
                            "x64": [
                                {
                                    "authenticodeHash": digest.hex(),
                                    "hashType": hash_algorithm,
                                }
                                for hash_algorithm, digest in hashes.items()
                            ]
                        }
                    }
                )
            )
            keystore = {
                "DefaultDbx": {
                    "arch": "x64",
                    "files": [
                        {
                            "path": str(json_path),
                            "signature_list_version": 2,
                        }
                    ],
                }
            }

            default_keys = build_default_keys(keystore)

        expected = b"".join(
            create_hash_signature_list(
                [digest],
                None,
                hash_algorithm,
                signature_list_version=2,
            )
            for hash_algorithm, digest in hashes.items()
        )
        self.assertEqual(default_keys["x64", "DefaultDbx"], expected)


if __name__ == "__main__":
    unittest.main()

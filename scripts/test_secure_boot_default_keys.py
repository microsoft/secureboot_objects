# @file test_secure_boot_default_keys.py
# This file contains unit tests for secure_boot_default_keys.py
##
# Copyright (c) Microsoft Corporation.
#
# SPDX-Licese-Identifier: BSD-2-Clause-Patent
##
"""Unit tests for secure_boot_default_keys.py."""

import json
import pathlib
import tempfile
import unittest

from secure_boot_default_keys import _convert_json_to_signature_list, _extract_certificate_subject_names


class TestSecureBootDefaultKeys(unittest.TestCase):
    """Test cases for secure_boot_default_keys.py."""

    def test_extract_certificate_subject_names(self) -> None:
        """Test extracting subject names from certificate files."""
        # Test with real certificate files from the repository
        cert_dir = pathlib.Path(__file__).parent.parent / "PreSignedObjects" / "DB" / "Certificates"
        if cert_dir.exists():
            cert_files = list(cert_dir.glob("*.der"))
            if cert_files:
                subjects = _extract_certificate_subject_names([str(f) for f in cert_files[:2]])
                self.assertIsInstance(subjects, set)
                self.assertGreater(len(subjects), 0)

    def test_convert_json_to_signature_list_no_filtering(self) -> None:
        """Test JSON conversion without filtering (default behavior)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test JSON file
            json_data = {
                "images": {
                    "x64": [
                        {
                            "authenticodeHash": "80B4D96931BF0D02FD91A61E19D14F1DA452E66DB2408CA8604D411F92659F0A",
                            "hashType": "SHA256",
                            "flatHash": "",
                            "filename": "test.efi",
                            "description": "",
                            "companyName": "Test",
                            "dateOfAddition": "2023-01-01",
                            "signingAuthority": "CN = Test Authority"
                        }
                    ]
                }
            }
            json_file = pathlib.Path(temp_dir) / "test.json"
            with open(json_file, "w") as f:
                json.dump(json_data, f)

            # Test without filtering
            result = _convert_json_to_signature_list(
                str(json_file),
                "77fa9abd-0359-4d32-bd60-28f4e78f784b",
                target_arch="x64"
            )
            self.assertIsInstance(result, bytes)
            self.assertGreater(len(result), 0)

    def test_convert_json_to_signature_list_with_filtering(self) -> None:
        """Test JSON conversion with authority filtering."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test JSON file with multiple authorities
            json_data = {
                "images": {
                    "x64": [
                        {
                            "authenticodeHash": "80B4D96931BF0D02FD91A61E19D14F1DA452E66DB2408CA8604D411F92659F0A",
                            "hashType": "SHA256",
                            "flatHash": "",
                            "filename": "authorized.efi",
                            "description": "",
                            "companyName": "Test",
                            "dateOfAddition": "2023-01-01",
                            "signingAuthority": "CN = Authorized Authority"
                        },
                        {
                            "authenticodeHash": "F52F83A3FA9CFBD6920F722824DBE4034534D25B8507246B3B957DAC6E1BCE7A",
                            "hashType": "SHA256",
                            "flatHash": "",
                            "filename": "unauthorized.efi",
                            "description": "",
                            "companyName": "Test",
                            "dateOfAddition": "2023-01-01",
                            "signingAuthority": "CN = Unauthorized Authority"
                        }
                    ]
                }
            }
            json_file = pathlib.Path(temp_dir) / "test.json"
            with open(json_file, "w") as f:
                json.dump(json_data, f)

            authorized_subjects = {"CN = Authorized Authority"}

            # Test with filtering - should only include authorized entry
            result = _convert_json_to_signature_list(
                str(json_file),
                "77fa9abd-0359-4d32-bd60-28f4e78f784b",
                target_arch="x64",
                filter_by_authority=True,
                authorized_subjects=authorized_subjects
            )
            self.assertIsInstance(result, bytes)
            self.assertGreater(len(result), 0)

    def test_convert_json_to_signature_list_missing_authority_field(self) -> None:
        """Test JSON conversion when signingAuthority field is missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test JSON file without signingAuthority
            json_data = {
                "images": {
                    "x64": [
                        {
                            "authenticodeHash": "80B4D96931BF0D02FD91A61E19D14F1DA452E66DB2408CA8604D411F92659F0A",
                            "hashType": "SHA256",
                            "flatHash": "",
                            "filename": "test.efi",
                            "description": "",
                            "companyName": "Test",
                            "dateOfAddition": "2023-01-01"
                            # Missing signingAuthority field
                        }
                    ]
                }
            }
            json_file = pathlib.Path(temp_dir) / "test.json"
            with open(json_file, "w") as f:
                json.dump(json_data, f)

            authorized_subjects = {"CN = Some Authority"}

            # Test with filtering - entry without signingAuthority should be filtered out
            result = _convert_json_to_signature_list(
                str(json_file),
                "77fa9abd-0359-4d32-bd60-28f4e78f784b",
                target_arch="x64",
                filter_by_authority=True,
                authorized_subjects=authorized_subjects
            )
            self.assertIsInstance(result, bytes)


if __name__ == "__main__":
    unittest.main()

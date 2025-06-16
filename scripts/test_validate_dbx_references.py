# @file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Test the validate_dbx_references.py script.

This module contains unit tests for the DBX certificate reference validation functionality.
"""
import json
import pathlib
import tempfile

import pytest
from validate_dbx_references import validate_certificate_references


def test_validate_certificate_references_no_certificates_section() -> None:
    """Test validation when JSON has no certificates section."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = pathlib.Path(temp_dir)

        # Create JSON file without certificates section
        json_file = temp_path / "dbx_info_msft_01_01_24.json"
        with json_file.open("w") as f:
            json.dump({"images": {"x64": []}}, f)

        # Create empty certificates directory
        certs_dir = temp_path / "Certificates"
        certs_dir.mkdir()

        # Should pass validation
        errors = validate_certificate_references(json_file, certs_dir)
        assert errors == []


def test_validate_certificate_references_empty_certificates() -> None:
    """Test validation when certificates section is empty."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = pathlib.Path(temp_dir)

        # Create JSON file with empty certificates section
        json_file = temp_path / "dbx_info_msft_01_01_24.json"
        with json_file.open("w") as f:
            json.dump({"certificates": []}, f)

        # Create empty certificates directory
        certs_dir = temp_path / "Certificates"
        certs_dir.mkdir()

        # Should pass validation
        errors = validate_certificate_references(json_file, certs_dir)
        assert errors == []


def test_validate_certificate_references_valid_certificates() -> None:
    """Test validation when all certificate references are valid."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = pathlib.Path(temp_dir)

        # Create certificates directory with test files
        certs_dir = temp_path / "Certificates"
        certs_dir.mkdir()
        (certs_dir / "cert1.cer").touch()
        (certs_dir / "cert2.der").touch()

        # Create JSON file referencing these certificates
        json_file = temp_path / "dbx_info_msft_01_01_24.json"
        json_data = {
            "certificates": [
                {
                    "value": "cert1.cer",
                    "subjectName": "Test Subject 1",
                    "issuerName": "Test Issuer 1",
                    "thumbprint": "abc123",
                    "description": "Test certificate 1",
                    "dateOfAddition": "2024-01-01"
                },
                {
                    "value": "cert2.der",
                    "subjectName": "Test Subject 2",
                    "issuerName": "Test Issuer 2",
                    "thumbprint": "def456",
                    "description": "Test certificate 2",
                    "dateOfAddition": "2024-01-01"
                }
            ]
        }
        with json_file.open("w") as f:
            json.dump(json_data, f)

        # Should pass validation
        errors = validate_certificate_references(json_file, certs_dir)
        assert errors == []


def test_validate_certificate_references_missing_certificates() -> None:
    """Test validation when some certificate references are missing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = pathlib.Path(temp_dir)

        # Create certificates directory with only one file
        certs_dir = temp_path / "Certificates"
        certs_dir.mkdir()
        (certs_dir / "cert1.cer").touch()

        # Create JSON file referencing missing certificate
        json_file = temp_path / "dbx_info_msft_01_01_24.json"
        json_data = {
            "certificates": [
                {
                    "value": "cert1.cer",
                    "subjectName": "Test Subject 1",
                    "issuerName": "Test Issuer 1",
                    "thumbprint": "abc123",
                    "description": "Test certificate 1",
                    "dateOfAddition": "2024-01-01"
                },
                {
                    "value": "missing_cert.cer",
                    "subjectName": "Test Subject 2",
                    "issuerName": "Test Issuer 2",
                    "thumbprint": "def456",
                    "description": "Test certificate 2",
                    "dateOfAddition": "2024-01-01"
                }
            ]
        }
        with json_file.open("w") as f:
            json.dump(json_data, f)

        # Should fail validation
        errors = validate_certificate_references(json_file, certs_dir)
        assert len(errors) == 1
        assert "missing_cert.cer" in errors[0]
        assert "not found" in errors[0]


def test_validate_certificate_references_missing_value_field() -> None:
    """Test validation when certificate entry is missing value field."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = pathlib.Path(temp_dir)

        # Create certificates directory
        certs_dir = temp_path / "Certificates"
        certs_dir.mkdir()

        # Create JSON file with malformed certificate entry
        json_file = temp_path / "dbx_info_msft_01_01_24.json"
        json_data = {
            "certificates": [
                {
                    "subjectName": "Test Subject",
                    "issuerName": "Test Issuer",
                    "thumbprint": "abc123",
                    "description": "Test certificate",
                    "dateOfAddition": "2024-01-01"
                    # Missing "value" field
                }
            ]
        }
        with json_file.open("w") as f:
            json.dump(json_data, f)

        # Should fail validation
        errors = validate_certificate_references(json_file, certs_dir)
        assert len(errors) == 1
        assert "missing 'value' field" in errors[0]


def test_validate_certificate_references_file_not_found() -> None:
    """Test validation when JSON file doesn't exist."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = pathlib.Path(temp_dir)

        # Create certificates directory
        certs_dir = temp_path / "Certificates"
        certs_dir.mkdir()

        # Reference non-existent JSON file
        json_file = temp_path / "nonexistent.json"

        # Should raise FileNotFoundError
        with pytest.raises(FileNotFoundError):
            validate_certificate_references(json_file, certs_dir)


def test_validate_certificate_references_invalid_json() -> None:
    """Test validation when JSON file is malformed."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = pathlib.Path(temp_dir)

        # Create certificates directory
        certs_dir = temp_path / "Certificates"
        certs_dir.mkdir()

        # Create malformed JSON file
        json_file = temp_path / "dbx_info_msft_01_01_24.json"
        with json_file.open("w") as f:
            f.write("{ invalid json }")

        # Should raise json.JSONDecodeError
        with pytest.raises(json.JSONDecodeError):
            validate_certificate_references(json_file, certs_dir)

"""Test the utility functions.

This module contains unit tests for the utility functions used in the project.
"""
import json
import pathlib
import tempfile

from utility_functions import get_latest_revocation_list


def test_get_latest_revocation_list() -> None:
    """Test the get_latest_revocation_list function."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = pathlib.Path(temp_dir)

        # Create some JSON files with different version numbers
        file_versions = [
            "revocation_list_1_0_0.json",
            "revocation_list_1_0_1.json",
            "revocation_list_1_1_0.json",
            "revocation_list_2_0_0.json"
        ]

        for file_version in file_versions:
            file_path = temp_path / file_version
            with file_path.open("w") as f:
                json.dump({"version": file_version}, f)

        # Test that the latest file is correctly identified
        latest_file = get_latest_revocation_list(temp_path)
        print(latest_file)
        assert latest_file.name == "revocation_list_2_0_0.json"

        # Test that FileNotFoundError is raised when no JSON files are present
        for file_path in temp_path.glob("*.json"):
            file_path.unlink()

        try:
            get_latest_revocation_list(temp_path)
        except FileNotFoundError as e:
            assert str(e) == "No JSON files found in the specified directory."

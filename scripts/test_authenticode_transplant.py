# @file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Tests for the authenticode_transplant script."""

import os
import subprocess
import sys
import tempfile
import unittest


class TestAuthenticodeTransplant(unittest.TestCase):
    """Test cases for authenticode transplant functionality."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        """Clean up test fixtures."""
        # Clean up test files if they exist
        for file in os.listdir(self.test_dir):
            os.remove(os.path.join(self.test_dir, file))
        os.rmdir(self.test_dir)

    def test_help_message(self) -> None:
        """Test that the help message can be generated without errors."""
        try:
            result = subprocess.run(
                [sys.executable, "scripts/authenticode_transplant.py", "--help"],
                cwd="/home/runner/work/secureboot_objects/secureboot_objects",
                capture_output=True,
                text=True,
                timeout=10
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("Transplant Authenticode signature", result.stdout)
            self.assertIn("source_pe", result.stdout)
            self.assertIn("target_pe", result.stdout)
            self.assertIn("output_pe", result.stdout)
            self.assertIn("--force", result.stdout)
            self.assertIn("--debug", result.stdout)
        except subprocess.TimeoutExpired:
            self.fail("Help command timed out")

    def test_missing_arguments(self) -> None:
        """Test that missing arguments are handled properly."""
        try:
            result = subprocess.run(
                [sys.executable, "scripts/authenticode_transplant.py"],
                cwd="/home/runner/work/secureboot_objects/secureboot_objects",
                capture_output=True,
                text=True,
                timeout=10
            )
            self.assertNotEqual(result.returncode, 0)  # Should fail with missing args
        except subprocess.TimeoutExpired:
            self.fail("Command with no args timed out")

    def test_nonexistent_source_file(self) -> None:
        """Test handling of non-existent source file."""
        target_file = os.path.join(self.test_dir, "target.exe")
        output_file = os.path.join(self.test_dir, "output.exe")

        # Create a dummy target file
        with open(target_file, 'wb') as f:
            f.write(b"dummy content")

        try:
            result = subprocess.run(
                [sys.executable, "scripts/authenticode_transplant.py",
                 "/nonexistent/source.exe", target_file, output_file],
                cwd="/home/runner/work/secureboot_objects/secureboot_objects",
                capture_output=True,
                text=True,
                timeout=10
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Source PE file not found", result.stderr)
        except subprocess.TimeoutExpired:
            self.fail("Command with nonexistent source timed out")

    def test_nonexistent_target_file(self) -> None:
        """Test handling of non-existent target file."""
        source_file = os.path.join(self.test_dir, "source.exe")
        output_file = os.path.join(self.test_dir, "output.exe")

        # Create a dummy source file
        with open(source_file, 'wb') as f:
            f.write(b"dummy content")

        try:
            result = subprocess.run(
                [sys.executable, "scripts/authenticode_transplant.py",
                 source_file, "/nonexistent/target.exe", output_file],
                cwd="/home/runner/work/secureboot_objects/secureboot_objects",
                capture_output=True,
                text=True,
                timeout=10
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Target PE file not found", result.stderr)
        except subprocess.TimeoutExpired:
            self.fail("Command with nonexistent target timed out")

    def test_debug_flag(self) -> None:
        """Test that debug flag is accepted."""
        source_file = os.path.join(self.test_dir, "source.exe")
        target_file = os.path.join(self.test_dir, "target.exe")
        output_file = os.path.join(self.test_dir, "output.exe")

        # Create dummy files
        with open(source_file, 'wb') as f:
            f.write(b"dummy content")
        with open(target_file, 'wb') as f:
            f.write(b"dummy content")

        try:
            result = subprocess.run(
                [sys.executable, "scripts/authenticode_transplant.py",
                 "--debug", source_file, target_file, output_file],
                cwd="/home/runner/work/secureboot_objects/secureboot_objects",
                capture_output=True,
                text=True,
                timeout=10
            )
            # Should fail because these aren't real PE files, but debug flag should be accepted
            self.assertNotEqual(result.returncode, 0)
        except subprocess.TimeoutExpired:
            self.fail("Command with debug flag timed out")


if __name__ == "__main__":
    unittest.main()

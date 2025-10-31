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
                cwd=os.getcwd(),
                capture_output=True,
                text=True,
                timeout=10
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("Authenticode signature tool for PE/UEFI binaries", result.stdout)
            self.assertIn("combine", result.stdout)
            self.assertIn("verify", result.stdout)
            self.assertIn("--debug", result.stdout)
        except subprocess.TimeoutExpired:
            self.fail("Help command timed out")

    def test_missing_arguments(self) -> None:
        """Test that missing arguments are handled properly."""
        try:
            result = subprocess.run(
                [sys.executable, "scripts/authenticode_transplant.py"],
                cwd=os.getcwd(),
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
                 "combine", "/nonexistent/source.exe", target_file, "--output", output_file],
                cwd=os.getcwd(),
                capture_output=True,
                text=True,
                timeout=10
            )
            self.assertNotEqual(result.returncode, 0)
            # The error message may be about file not found or PE validation
            self.assertTrue("not found" in result.stderr or "FileNotFoundError" in result.stderr)
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
                 "combine", source_file, "/nonexistent/target.exe", "--output", output_file],
                cwd=os.getcwd(),
                capture_output=True,
                text=True,
                timeout=10
            )
            self.assertNotEqual(result.returncode, 0)
            # The error message may be about file not found or PE validation
            self.assertTrue("not found" in result.stderr or "FileNotFoundError" in result.stderr)
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
                 "--debug", "combine", source_file, target_file, "--output", output_file],
                cwd=os.getcwd(),
                capture_output=True,
                text=True,
                timeout=10
            )
            # Should fail because these aren't real PE files, but debug flag should be accepted
            self.assertNotEqual(result.returncode, 0)
        except subprocess.TimeoutExpired:
            self.fail("Command with debug flag timed out")

    def test_combine_help_message(self) -> None:
        """Test that the combine subcommand help message works."""
        try:
            result = subprocess.run(
                [sys.executable, "scripts/authenticode_transplant.py", "combine", "--help"],
                cwd=os.getcwd(),
                capture_output=True,
                text=True,
                timeout=10
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("sources", result.stdout)
            self.assertIn("--output", result.stdout)
            self.assertIn("--nested", result.stdout)
        except subprocess.TimeoutExpired:
            self.fail("Combine help command timed out")

    def test_verify_help_message(self) -> None:
        """Test that the verify subcommand help message works."""
        try:
            result = subprocess.run(
                [sys.executable, "scripts/authenticode_transplant.py", "verify", "--help"],
                cwd=os.getcwd(),
                capture_output=True,
                text=True,
                timeout=10
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("source", result.stdout)
            self.assertIn("--output-dir", result.stdout)
        except subprocess.TimeoutExpired:
            self.fail("Verify help command timed out")

    def test_verify_nonexistent_file(self) -> None:
        """Test verify subcommand with non-existent file."""
        try:
            result = subprocess.run(
                [sys.executable, "scripts/authenticode_transplant.py",
                 "verify", "/nonexistent/file.exe"],
                cwd=os.getcwd(),
                capture_output=True,
                text=True,
                timeout=10
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue("not found" in result.stderr or "FileNotFoundError" in result.stderr)
        except subprocess.TimeoutExpired:
            self.fail("Verify command with nonexistent file timed out")


if __name__ == "__main__":
    unittest.main()

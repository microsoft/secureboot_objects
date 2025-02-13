# @file test_prepare.py
# This file contains unit tests for prepare.py
##
# Copyright (c) Microsoft Corporation.
#
# SPDX-Licese-Identifier: BSD-2-Clause-Patent
##
"""Unit tests for prepare.py."""
import pathlib
import shutil
import sys
import tempfile

import prepare_firmware_binaries as prepare_firmware_binaries

EXPECTED_FILES = 12

def test_layout(tmpdir: pathlib.Path) -> None:
    """Tests that files are correctly copied, and all zip / gztars are created."""
    IN_FILE = "Artifacts"
    OUT_FILE = "ReleaseArtifacts"

    artifacts = pathlib.Path(tmpdir / IN_FILE)
    artifacts.mkdir()

    folder_list = ["Arm", "Aarch64", "Ia32", "X64", "Imaging"]
    file_list = ["Default3PDb.bin", "DefaultDb.bin", "DefaultDbx.bin", "DefaultKEK.bin", "DefaultPK.bin", "README.md"]

    for folder in folder_list:
        folder = artifacts / folder
        folder.mkdir()

        for file in file_list:
            file = folder / file
            file.touch()

    sys.argv = [
        "prepare.py",
        str(tmpdir / IN_FILE),
        "--version",
        "1.0.0",
        "-o",
        str(tmpdir / OUT_FILE),
    ]
    prepare_firmware_binaries.main()

    zip_file_list = list(pathlib.Path(tmpdir / OUT_FILE).glob("*"))

    assert len(zip_file_list) == 11

    for file in zip_file_list:
        if file.suffix == ".md":
            continue

        with tempfile.TemporaryDirectory() as temp_unzip_dir:
            shutil.unpack_archive(file, temp_unzip_dir)

            assert len(list(pathlib.Path(temp_unzip_dir).glob("*"))) == EXPECTED_FILES

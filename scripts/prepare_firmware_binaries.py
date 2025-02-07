# @file
#
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""A command line script to prepare the files generated from secure_boot_default_keys.py for a github release."""
import argparse
import logging
import pathlib
import shutil
import sys
import tempfile

LAYOUT = {
    "edk2-arm-secureboot-binaries": "Arm",
    "edk2-aarch64-secureboot-binaries": "Aarch64",
    "edk2-ia32-secureboot-binaries": "Ia32",
    "edk2-x64-secureboot-binaries": "X64",
}

def main() -> int:
    """Entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Organizes and zips the files for a release.")
    parser.add_argument("input", type=pathlib.Path,
                        help="The directory containing the files to be Prepared.")
    parser.add_argument("--version", required=True,
                        help="The version number of the release.")
    parser.add_argument("-o","--output", default="FirmwareArchive", type = pathlib.Path,
                        help="The output directory for prepared files.")
    args = parser.parse_args()

    out_path = args.output
    in_path = args.input
    # Make directory if it doesn't exist. Delete any files in it if it does.
    out_path.mkdir(parents=True, exist_ok=True)
    for file_path in out_path.rglob("*"):
        if file_path.is_file():
            file_path.unlink()

    for name, arch in LAYOUT.items():
        tmp_dir = tempfile.TemporaryDirectory()
        pathlib.Path(tmp_dir.name, "version").write_text(args.version)
        if not (in_path / arch).exists():
            raise RuntimeError(f"Missing {arch} directory in {in_path}")
        shutil.copytree(in_path / arch, pathlib.Path(tmp_dir.name), dirs_exist_ok=True)

        shutil.make_archive(out_path / name, "zip", tmp_dir.name)
        shutil.make_archive(out_path / name, "gztar", tmp_dir.name)


if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s: %(message)s")
    sys.exit(main())

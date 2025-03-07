# @file
#
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""A command line script to prepare the files generated from secure_boot_default_keys.py for a github release."""

import argparse
import json
import logging
import pathlib
import shutil
import sys
import tempfile

from utility_functions import get_signed_payload_receipt, get_unsigned_payload_receipt

LAYOUT = {
    "edk2-arm-secureboot-binaries": "Arm",
    "edk2-aarch64-secureboot-binaries": "Aarch64",
    "edk2-ia32-secureboot-binaries": "Ia32",
    "edk2-x64-secureboot-binaries": "X64",
}

INFORMATION = (pathlib.Path(__file__).parent / "information" / "firmware_binaries_information.md").read_text()
LICENSE = (pathlib.Path(__file__).parent / "information" / "prebuilt_binaries_license.md").read_text()

def get_receipt(bin_file: str) -> dict:
    """Attempts to retrieve a receipt for the given binary file using multiple methods.

    This function tries to obtain a receipt for the provided binary file by sequentially
    calling the `get_unsigned_payload_receipt` and `get_signed_payload_receipt` methods.
    If both methods fail, it logs a warning and raises a ValueError.

    Args:
        bin_file (str): The path to the binary file for which to get the receipt.

    Returns:
        The receipt obtained from one of the methods.

    Raises:
        ValueError: If neither method is able to retrieve a receipt for the binary file.
    """
    for method in (get_unsigned_payload_receipt, get_signed_payload_receipt):
        try:
            return method(bin_file)
        except Exception:
            pass

    logging.warning(f"Failed to get receipt for {bin_file}")
    raise ValueError("Failed to get receipt")

def main() -> int:
    """Entry point for the script."""
    parser = argparse.ArgumentParser(description="Organizes and zips the files for a release.")
    parser.add_argument("input", type=pathlib.Path, help="The directory containing the files to be Prepared.")
    parser.add_argument("--version", required=True, help="The version number of the release.")
    parser.add_argument(
        "-o", "--output", default="FirmwareArchive", type=pathlib.Path, help="The output directory for prepared files."
    )
    args = parser.parse_args()

    out_path = args.output
    in_path = args.input
    # Make directory if it doesn't exist. Delete any files in it if it does.
    out_path.mkdir(parents=True, exist_ok=True)
    for file_path in out_path.rglob("*"):
        if file_path.is_file():
            file_path.unlink()

    readme = ""
    readme += INFORMATION
    readme += "\n\n" + "-" * 80 + "\n\n"
    readme += LICENSE

    readme_path = out_path / "README.md"
    readme_path.write_text(readme)

    for name, arch in LAYOUT.items():
        tmp_dir = tempfile.TemporaryDirectory()
        pathlib.Path(tmp_dir.name, "version").write_text(args.version)
        if not (in_path / arch).exists():
            raise RuntimeError(f"Missing {arch} directory in {in_path}")
        shutil.copytree(in_path / arch, pathlib.Path(tmp_dir.name), dirs_exist_ok=True)

        tmp_path = pathlib.Path(tmp_dir.name)
        for bin_file in tmp_path.rglob("*.bin"):
            receipt = {}

            receipt = get_receipt(bin_file)
            receipt_json = json.dumps(receipt, indent=4)
            receipt_path = bin_file.with_suffix('.json')
            receipt_path.write_text(receipt_json)

        shutil.make_archive(out_path / name, "zip", tmp_dir.name)
        shutil.make_archive(out_path / name, "gztar", tmp_dir.name)

        logging.info(f"Created archives for {name} in {out_path}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    sys.exit(main())

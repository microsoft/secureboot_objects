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

from utility_functions import get_signed_payload_receipt

INFORMATION = (pathlib.Path(__file__).parent / "information" / "signed_binaries_information.md").read_text()
LICENSE = (pathlib.Path(__file__).parent.parent / "License.txt").read_text()

LAYOUT = {
    "edk2-2011-signed-secureboot-binaries": ["SignedByKEK2011"],
    "edk2-2023-signed-secureboot-binaries": ["SignedByKEK2023"],
    "edk2-2011-optional-signed-secureboot-binaries": ["Optional"],
}

def main() -> int:
    """Entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Organizes and zips the files for a release.")
    parser.add_argument("input", type=pathlib.Path,
                        help="The directory containing the files to be Prepared.")
    parser.add_argument("--version", required=True,
                        help="The version number of the release.")
    parser.add_argument("-o","--output", default="SignedArchive", type = pathlib.Path,
                        help="The output directory for prepared files.")
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
    readme += '\n\n' + "-" * 80 + "\n\n"
    readme += LICENSE

    readme_path = out_path / "README.md"
    readme_path.write_text(readme)

    for name, sources in LAYOUT.items():
        tmp_dir = tempfile.TemporaryDirectory()
        tmp_path = pathlib.Path(tmp_dir.name)
        (tmp_path / "version").write_text(args.version)

        for source in sources:
            source_path = in_path / source
            if not source_path.exists():
                raise RuntimeError(f"Missing {source} directory in {in_path}")
            # When an archive draws from a single source directory, its contents are
            # placed at the archive root. When it aggregates multiple source directories,
            # each is preserved under its own subfolder to keep them distinct.
            destination = tmp_path if len(sources) == 1 else tmp_path / source
            shutil.copytree(source_path, destination, dirs_exist_ok=True)

        for signed_file in (*tmp_path.rglob("*.bin"), *tmp_path.rglob("*.efiauth2")):
            receipt = get_signed_payload_receipt(signed_file)
            receipt_json = json.dumps(receipt, indent=4)
            receipt_path = signed_file.with_suffix('.json')
            receipt_path.write_text(receipt_json)

        shutil.make_archive(out_path / name, "zip", tmp_dir.name)
        shutil.make_archive(out_path / name, "gztar", tmp_dir.name)

        logging.info(f"Created archives for {name} in {out_path}")


if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s: %(message)s")
    sys.exit(main())

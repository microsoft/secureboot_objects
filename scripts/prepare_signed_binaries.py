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

INSTRUCTIONS = r"""
# Information

Most users should depend on the Operating system to update the Secure Boot Signatures as otherwise the
system will not boot. In a best case scenario, the system will boot but the user will be presented with
a EFI_SECURIT_VIOLATION error message. Doing this out of band may effect cause security enforcement
tools (such as BitLocker) to fail to boot the system.

Advanced Users who are familiar with the UEFI Secure Boot process can use these binaries to update the
Secure Boot Signatures on their system.

## edk2-2011-signed-secureboot-binaries

Background:
    - These binaries are signed with a leaf certificate of the Microsoft UEFI CA 2011 KEK.
    - These binaries should be used for systems that trust the Microsoft UEFI CA 2011 KEK certificate
    - These binaries hashes are broken up by architecture
        - X64
        - Ia32
        - Arm
        - Aarch64
    - Purely hash based revocations. These do not contain the 2011 Windows CA nor do they contain SVNs.
    - These binaries are the most compatible with the most systems consult the
    `PreSignedObjects\DBX\dbx_info_msft_<date>.json` file for more information.

## edk2-2011-optional-signed-secureboot-binaries

Background:
    - These binaries are considered optional because the ecosystem is undergoing a transition to new
    certificates. Not all platforms can be updated yet without a firmware update.
    - If a platform does take these optional updates, they will be unable to boot existing Windows boot
    media. More information to follow.
    - These binaries are signed with a leaf certificate of the Microsoft UEFI CA 2011 KEK.
    - These binaries should be used for systems that trust the Microsoft UEFI CA 2011 KEK certificate
    - They are broken up by:
        - DB
            - `DBUpdate2024` Contains a 2011 MSFT KEK Signed 2023 Windows CA DB update
        - DBX
            -  `DBXUpdate2024.bin` Contains a 2011 MSFT KEK Signed revocation that revokes 2011
            Windows CA and SVNs
            - `DBXUpdateSVN` Contains a 2011 MSFT KEK Signed revocation of SVNs
    - These binaries are the lease compatible and will break existing Windows boot media. Consult the
    `PreSignedObjects\DBX\dbx_info_msft_<date>.json` file for more information.
"""

LAYOUT = {
    "edk2-2011-signed-secureboot-binaries": "DBX",
    "edk2-2011-optional-signed-secureboot-binaries": "Optional",
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

    readme_path = out_path / "README.md"
    readme_path.write_text(INSTRUCTIONS)

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

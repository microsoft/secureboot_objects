# @file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""A command line script used to build the authenticated variable structures for Secureboot."""
import base64
import csv
import datetime
import io
import logging
import uuid
from pathlib import Path
from tempfile import TemporaryFile
from typing import Union

from edk2toollib.uefi.authenticated_variables_structure_support import (
    EfiSignatureDataEfiCertSha256,
    EfiSignatureDataFactory,
    EfiSignatureList,
    EfiTime,
)
from edk2toollib.uefi.wincert import WinCertUefiGuid

DEFAULT_MS_SIGNATURE_GUID = "77fa9abd-0359-4d32-bd60-28f4e78f784b"
ARCH_MAP = {"64-bit": "x64", "32-bit": "ia32", "32-bit ARM": "arm", "64-bit ARM": "aarch64"}


def _is_pem_encoded(certificate_data: Union[str, bytes]) -> bool:
    """This function is used to check if a certificate is pem encoded (base64 encoded).

    Args:
        certificate_data (str | bytes): The certificate to check.

    Returns:
        bool: True if the certificate is pem encoded, False otherwise.
    """
    try:
        if isinstance(certificate_data, str):
            # If there's any unicode here, an exception will be thrown and the function will return false
            sb_bytes = bytes(certificate_data, "ascii")
        elif isinstance(certificate_data, bytes):
            sb_bytes = certificate_data
        else:
            raise ValueError("Argument must be string or bytes")

        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception:
        return False


def _convert_pem_to_der(certificate_data: Union[str, bytes]) -> bytes:
    """This function is used to convert a pem encoded certificate to a der encoded certificate.

    Args:
        certificate_data: The certificate to convert.

    Returns:
        bytes: The der encoded certificate.
    """
    if isinstance(certificate_data, str):
        # If there's any unicode here, an exception will be thrown and the function will return false
        certificate_data = bytes(certificate_data, "ascii")

    return base64.b64decode(certificate_data)


def _invalid_file(file: str, **kwargs: any) -> None:
    """This function is used to handle invalid filetypes.

    Args:
        file: The path to the file

    Optional Args:
        **kwargs: Additional arguments to be passed to the function (These will be intentionally ignored)

    Raises:
        ValueError: If the file is invalid, raise a ValueError.
    """
    raise ValueError(f"Invalid filetype for conversion: {file}")


def _convert_crt_to_signature_list(file: str, signature_owner: str = DEFAULT_MS_SIGNATURE_GUID, **kwargs: any) -> bytes:
    """This function converts a single crt file to a signature list.

    Args:
        file: The path to the crt file
        signature_owner: The signature owner. Defaults to DEFAULT_MS_SIGNATURE_GUID.

    Optional Args:
        **kwargs: Additional arguments to be passed to the function (These will be intentionally ignored)

    Returns:
        bytes: The signature list
    """
    if signature_owner is not None and not isinstance(signature_owner, uuid.UUID):
        signature_owner = uuid.UUID(signature_owner)

    siglist = EfiSignatureList(typeguid=EfiSignatureDataFactory.EFI_CERT_X509_GUID)

    with open(file, "rb") as crt_file, TemporaryFile() as temp_file:
        certificate = crt_file.read()
        if _is_pem_encoded(certificate):
            certificate = _convert_pem_to_der(certificate)

        temp_file.write(certificate)
        temp_file.seek(0)

        sigdata = EfiSignatureDataFactory.create(EfiSignatureDataFactory.EFI_CERT_X509_GUID, temp_file, signature_owner)

        # X.509 certificates are variable size, so they must be contained in their own signature list
        siglist.AddSignatureHeader(None, SigSize=sigdata.get_total_size())
        siglist.AddSignatureData(sigdata)

    return siglist.encode()


def _convert_csv_to_signature_list(
    file: str, signature_owner: str = DEFAULT_MS_SIGNATURE_GUID, target_arch: str = None, **kwargs: any
) -> bytes:
    """This function is used to handle the csv files.

    This function expects to be given a csv file with the following format:
    SHA 256 FLAT, PE256 Authenticode, filename, Architecture, Partner, CVEs, Revocation List Date

    This file may be found on uefi.org/revocationlistfile

    Args:
        file: The path to the crt file
        signature_owner: The signature owner. Defaults to DEFAULT_MS_SIGNATURE_GUID.
        target_arch: the arch to filter on when parsing the csv

    Optional Args:
        **kwargs: Additional arguments to be passed to the function (These will be intentionally ignored)

    Returns:
        bytes: The signature list
    """
    if signature_owner is not None and not isinstance(signature_owner, uuid.UUID):
        signature_owner = uuid.UUID(signature_owner)

    siglist = EfiSignatureList(typeguid=EfiSignatureDataFactory.EFI_CERT_SHA256_GUID)

    with open(file, "r") as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=",")
        for i, row in enumerate(csv_reader):
            if i == 0:
                siglist.AddSignatureHeader(None, SigSize=EfiSignatureDataEfiCertSha256.STATIC_STRUCT_SIZE)
                continue

            authenticode_hash = row[1]
            architecture = ARCH_MAP.get(row[3], None)

            if architecture is None:
                raise ValueError(f"Invalid architecture: {architecture}")
            if target_arch is not None and architecture != target_arch:
                logging.debug(f"Skipping {architecture} because it is not in the target architectures.")
                continue

            sigdata = EfiSignatureDataEfiCertSha256(
                None, None, bytearray.fromhex(authenticode_hash), sigowner=signature_owner
            )
            siglist.AddSignatureData(sigdata)

    return siglist.encode()


def _convert_to_empty_auth_var(esl_payload: bytes) -> bytes:
    """This function is used to add a empty authenticated variable header to a secure boot efi signature list.

    Args:
        esl_payload: The secure boot efi signature list

    Returns:
        bytes: The wrapped empty authenticated secure boot efi signature list
    """
    # See the following for code implementation:
    # https://github.com/microsoft/mu_tiano_plus/blob/5c96768c404d1e4e32b1fea6bfd83e588c0f5d67/SecurityPkg/Library/AuthVariableLib/AuthService.c#L656C13-L656C52
    #
    # This is the ASN.1 structure and it's encoding of the AUTHINFO2 signature currently needed to initialize
    # a secure boot variable without being signed:
    #
    # ContentInfo SEQUENCE (4 elem)
    #   contentType ContentType [?] INTEGER 1
    #   content [0] [?] SET (1 elem)
    #       ANY SEQUENCE (2 elem)
    #           OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1 sha-256 (NIST Algorithm)
    #           NULL
    #   SEQUENCE (1 elem)
    #       OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
    #   SET (0 elem)
    #
    empty_pkcs7_signature = bytearray(
        [
            0x30,
            0x23,
            0x02,
            0x01,
            0x01,
            0x31,
            0x0F,
            0x30,
            0x0D,
            0x06,
            0x09,
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            0x01,
            0x05,
            0x00,
            0x30,
            0x0B,
            0x06,
            0x09,
            0x2A,
            0x86,
            0x48,
            0x86,
            0xF7,
            0x0D,
            0x01,
            0x07,
            0x01,
            0x31,
            0x00,
        ]
    )

    buffer = io.BytesIO()
    buffer.write(empty_pkcs7_signature)
    buffer.seek(0)

    # Microsoft uses  "2010-03-06T19:17:21Z" for all secure boot UEFI authenticated variables
    efi_time = EfiTime(time=datetime.datetime(2010, 3, 6, 19, 17, 21))
    auth_info2 = WinCertUefiGuid()

    # Add the empty PKCS7 signature to the AUTHINFO2 structure
    auth_info2.add_cert_data(buffer)

    # Create the header for the authenticated variable
    header = efi_time.encode() + auth_info2.encode()

    # Return the header + the original secure boot efi signature list
    return header + esl_payload


def build_default_keys(keystore: dict) -> dict:
    """This function is used to build the default keys for secure boot.

    Args:
        keystore: A [variable, arch] keyed dictionary containing the matching file in hex format

    Returns:
        a dictionary containing the hex representation of the file

    """
    logging.info("Building default keys for secure boot.")

    default_keys = {}

    # Add handlers here for different file types.
    file_handler = {
        ".crt": _convert_crt_to_signature_list,
        # DER is just a more specific certificate format than CRT
        ".der": _convert_crt_to_signature_list,
        ".csv": _convert_csv_to_signature_list,
    }

    # The json file should be a list of signatures including the owner of the signature.
    for variable in keystore:
        for arch in set(ARCH_MAP.values()):
            # Skip generating this blob if arch is specified and it does not match
            if keystore[variable].get("arch", arch) != arch:
                logging.debug(f"Skipping {variable} for {arch} due to config file settings.")
                continue

            # The signature database is a byte array that will be added to the default keys.
            signature_database = bytes()

            signature_owner = keystore[variable].get("signature_owner", "77fa9abd-0359-4d32-60bd-28f4e78f784b")
            files = keystore[variable]["files"]
            # The files should be handled differently depending on the file extension.
            for file_dict in files:
                # Get the file extension.\
                file_path = Path(file_dict["path"])
                file_ext = file_path.suffix.lower()

                convert_handler = file_handler.get(file_ext, _invalid_file)

                logging.info("Converting %s to signature list.", file_path)

                signature_database += convert_handler(file=file_path, signature_owner=signature_owner, target_arch=arch)

                logging.info("Appended %s to signature database for variable %s.", file_path, variable)

            default_keys[arch, variable] = signature_database

            logging.debug("Signature Database for %s:", variable)

    return default_keys


def create_readme(keystore: dict, arch: str) -> str:
    """Generates a README.md file for a given architecture.

    Args:
        keystore: A dictionary containing the keys mapped to certificates and hashes.
        arch: The architecture to filter on when creating the readme

    Returns:
        a string representing the readme.
    """
    readme = f"""# {arch.capitalize()} Secure Boot Defaults

This external dependency contains the default values suggested by microsoft the KEK, DB, and DBX UEFI variables.

Additionally, it contains an optional shared PK certificate that may be used as the root of trust for the system.
The shared PK certificate is an offering from Microsoft. Instead of a original equipment manufacturer (OEM)
managed PK, an OEM may choose to use the shared PK certificate managed by Microsoft. Partically, this may be
useful as default on non production code provided to an OEM by an indenpendent vendor (IV).

1. The PK (Platform Key) is a single certificate that is the root of trust for the system. This certificate is used
    to verify the KEK.
2. The KEK (Key Exchange Key) is a list of certificates that verify the signature of other keys attempting to update
   the DB and DBX.
3. The DB (Signature Database) is a list of certificates that verify the signature of a binary attempting to execute
   on the system.
4. The DBX (Forbidden Signature Database) is a list of signatures that are forbidden from executing on the system.

Please review [Microsoft's documentation](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11#15-keys-required-for-secure-boot-on-all-pcs)
for more information on key requirements if appending to the defaults provided in this external dependency.

## Firmware Folder
This folder contains the defaults in a EFI Signature List Format. This format is used by the UEFI firmware to
initialize the secure boot variables.
Thses files are in the format described by [EFI_SIGNATURE_DATA](https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html?highlight=authenticated%20variable#efi-signature-data)

## Imaging Folder
This folder contains the defaults in a format that may be used by imaging tools during imagine (such as tools that call
SetFirmwareVariableEx(..) like [WinPE](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-intro?view=windows-11))
to initialize the secure boot variables. These files have a empty authenticated variable header prepended to the EFI Signature List.
These variables are not signed and may be used to initialize the secure on systems that support this feature.

The additional data appended is a empty [EFI_VARIABLE_AUTHENICATION_2](https://uefi.org/specs/UEFI/2.10/08_Services_Runtime_Services.html?highlight=efi_time#using-the-efi-variable-authentication-2-descriptor)
descriptor and is as follows:
[EFI_TIME](https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf#page=158) +
[WIN_CERTIFICATE_UEFI_GUID](https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html?highlight=authenticated%20variable#win-certificate-uefi-guid) +
[PKCS7](https://tools.ietf.org/html/rfc2315#section-9.1) +
Data

Where the PKCS7 is a empty signature with the following ASN.1 structure:
```text
ContentInfo SEQUENCE (4 elem)
    contentType ContentType [?] INTEGER 1
    content [0] [?] SET (1 elem)
        ANY SEQUENCE (2 elem)
            OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1 sha-256 (NIST Algorithm)
            NULL
    SEQUENCE (1 elem)
        OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
    SET (0 elem)
```

For some firmware implementations, the PK is required to be at-least self signed during the imaging process.
However [Project Mu has a relaxed implementation](https://github.com/microsoft/mu_tiano_plus/blob/5c96768c404d1e4e32b1fea6bfd83e588c0f5d67/SecurityPkg/Library/AuthVariableLib/AuthService.c#L656C13-L656C52)
that allows for the PK to use an empty signature.

"""  # noqa: E501
    for key, value in keystore.items():
        # Filter out Tables not used for the specific architecture
        if keystore[key].get("arch", arch) != arch:
            logging.debug(f"Skipping {key} for {arch} due to config file settings.")
            continue
        readme += f"\n## {key}\n\n"

        if value.get("help", ""):
            readme += f"{_split_text_by_length(value.get('help', ''))}\n\n"
        readme += "Files Included:\n\n"

        for file_dict in value["files"]:
            # Filter out Files not used for the specific architecture
            if file_dict.get("arch", arch) != arch:
                continue
            if file_dict.get("url", None) is not None:
                readme += f"* <{file_dict['url']}>\n"
    return bytes(readme, "utf-8")


def create_folder(directory: Path):
    """Creates a folder if it does not exist.

    Args:
        directory: The path to the folder to create.

    Returns:
        None
    """
    directory.mkdir(exist_ok=True, parents=True)
    directory.touch()


def main() -> int:
    """Main entry point into the tool."""
    import argparse
    import pathlib

    import tomli as tomllib

    parser = argparse.ArgumentParser(description="Build the default keys for secure boot.")
    parser.add_argument(
        "--keystore",
        help="A json file containing the keys mapped to certificates and hashes.",
        default="keystore.toml",
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        type=pathlib.Path,
        default=pathlib.Path.cwd() / "Artifacts",
        help="The output directory for the default keys.",
    )

    args = parser.parse_args()

    with open(args.keystore, "rb") as f:
        keystore = tomllib.load(f)

        # Build the default key binaries; filters on requested architectures in the configuration file.
        default_keys = build_default_keys(keystore)
        # Write the keys to the output directory and create a README.md file for each architecture.
        for key, value in default_keys.items():
            arch, variable = key

            parent = Path(args.output, arch.capitalize())
            create_folder(parent)

            firmware_dir = Path(parent, "Firmware")
            create_folder(firmware_dir)

            out_file = Path(firmware_dir, f"{variable}.bin")
            if out_file.exists():
                out_file.unlink()
            with open(out_file, "wb") as f:
                f.write(value)

            imaging_dir = Path(parent, "Imaging")
            create_folder(imaging_dir)

            out_file = Path(imaging_dir, f"{variable}.bin")
            if out_file.exists():
                out_file.unlink()
            with open(out_file, "wb") as f:
                f.write(_convert_to_empty_auth_var(value))

            readme_path = Path(parent, "README.md")
            if readme_path.exists():
                readme_path.unlink()
            with open(readme_path, "wb") as f:
                f.write(create_readme(keystore, arch))
    return 0


def _split_text_by_length(text: str, max_length: int = 120) -> str:
    """Inserts newline characters into text to ensure that no line is longer than max_length.

    Args:
        text: The text to split.
        max_length: The maximum length of each line.

    Returns:
        str: The text with newline characters inserted.
    """
    lines = []
    current_line = ""

    words = text.split()
    for word in words:
        if len(current_line) + len(word) + 1 <= max_length:
            if current_line:
                current_line += " "
            current_line += word
        else:
            lines.append(current_line)
            current_line = word
    if current_line:
        lines.append(current_line)

    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    sys.exit(main())

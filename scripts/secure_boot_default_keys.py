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
import json
import logging
import os
import pathlib
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

# Random UUID used as the signature owner if none is provided.
INSTANCE_SIGNATURE_OWNER = str(uuid.uuid4())

ARCH_MAP = {"64-bit": "x64", "32-bit": "ia32", "32-bit ARM": "arm", "64-bit ARM": "aarch64"}

FIRMWARE_INFORMATION = (pathlib.Path(__file__).parent / "information" / "firmware_defaults_information.md").read_text()
IMAGING_INFORMATION = (pathlib.Path(__file__).parent / "information" / "imaging_binaries_information.md").read_text()
LICENSE = (pathlib.Path(__file__).parent / "information" / "prebuilt_binaries_license.md").read_text()

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


def _convert_crt_to_signature_list(file: str, signature_owner: str, **kwargs: any) -> bytes:
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


def _convert_csv_to_signature_list(file: str, signature_owner: str, target_arch: str = None, **kwargs: any) -> bytes:
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

def _convert_json_to_signature_list(file: str, signature_owner: str, target_arch: str = None, **kwargs: any) -> bytes:
    """Converts a JSON file containing image hashes to an EFI signature list.

    Args:
        file (str): The path to the JSON file containing the image hashes.
        signature_owner (str): The UUID of the signature owner. If not a UUID instance, it will be converted.
        target_arch (str, optional): The target architecture to filter the hashes. Defaults to None.
        **kwargs (any): Additional keyword arguments.

    Returns:
        bytes: The encoded EFI signature list.

    Raises:
        ValueError: If the hash type in the JSON file is not 'SHA256'.
    Example JSON format:
        {
            "images": {
                "x64": [
                    {
                        "authenticodeHash": "80B4D96931BF0D02FD91A61E19D14F1DA452E66DB2408CA8604D411F92659F0A",
                        "hashType": "SHA256",
                        "flatHash": "",
                        "filename": "shim.efi",
                        "description": "",
                        "companyName": "Unknown",
                        "dateOfAddition": "2018-04-01",
                        "signingAuthority": "CN = Microsoft Corporation UEFI CA 2011"
                    }
                ]
            }
        }
    """
    if signature_owner is not None and not isinstance(signature_owner, uuid.UUID):
        signature_owner = uuid.UUID(signature_owner)

    siglist = EfiSignatureList(typeguid=EfiSignatureDataFactory.EFI_CERT_SHA256_GUID)
    siglist.AddSignatureHeader(None, SigSize=EfiSignatureDataEfiCertSha256.STATIC_STRUCT_SIZE)

    with open(file, "r") as json_file:
        data = json.load(json_file)

        hashes = data["images"]
        for arch in hashes:
            if target_arch is not None and arch != target_arch:
                logging.debug(f"Skipping {arch} because it is not in the target architectures.")
                continue

            for hash in hashes[arch]:
                authenticode_hash = hash["authenticodeHash"]

                # Check if the hash type is SHA256
                # This may be expanded in the future to support other hash types
                if hash["hashType"] != "SHA256":
                    raise ValueError(f"Invalid hash type: {hash['hashType']}")

                sigdata = EfiSignatureDataEfiCertSha256(
                    None, None, bytearray.fromhex(authenticode_hash), sigowner=signature_owner
                )

                siglist.AddSignatureData(sigdata)

    return siglist.encode()

def _create_time_based_payload(esl_payload: bytes) -> bytes:
    """This function creates a authenticated variable with an empty signature for the provided payload.

    Args:
        esl_payload (bytes): The secure boot efi signature list

    Returns:
        (bytes): an authenticated variable with an empty signature
    """
    # See the following for code implementation:
    # https://github.com/microsoft/mu_tiano_plus/blob/5c96768c404d1e4e32b1fea6bfd83e588c0f5d67/SecurityPkg/Library/AuthVariableLib/AuthService.c#L656C13-L656C52
    #
    # This is the ASN.1 structure and it's encoding of the AUTHINFO2 signature currently needed to initialize
    # a secure boot variable without being signed:

    # ContentInfo SEQUENCE (4 elem)
    content_info_sequence = [0x30, 0x23]
    #   contentType ContentType [?] INTEGER 1
    content_type_integer = [0x02, 0x01, 0x01]
    #   content [0] [?] SET (1 elem)
    content_set = [0x31, 0x0F]
    #       ANY SEQUENCE (2 elem)
    any_sequence = [
        0x30, 0x0D,
        # OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1 (sha-256, NIST Algorithm)
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        # NULL
        0x05, 0x00,
    ]
    #   SEQUENCE (1 elem)
    sequence = [
        0x30, 0x0B,
        # OBJECT IDENTIFIER 1.2.840.113549.1.7.1 (data, PKCS #7)
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
    ]
    # SET (0 elements)
    set_empty = [0x31, 0x00]

    # Combine all sections
    empty_pkcs7_signature = bytearray(
        content_info_sequence +
        content_type_integer +
        content_set +
        any_sequence +
        sequence +
        set_empty
    )

    buffer = io.BytesIO()
    buffer.write(empty_pkcs7_signature)
    buffer.seek(0)

    # Microsoft uses "2010-03-06T19:17:21Z" for all secure boot UEFI authenticated variables
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
        ".der": _convert_crt_to_signature_list,  # DER is just a more specific certificate format than CRT
        ".csv": _convert_csv_to_signature_list,
        ".json": _convert_json_to_signature_list,
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

            files = keystore[variable]["files"]
            # The files should be handled differently depending on the file extension.
            for file_dict in files:
                # Get the file extension.
                file_path = Path(file_dict["path"])
                file_ext = file_path.suffix.lower()

                signature_owner = file_dict.get("signature_owner", None)
                if signature_owner is None:
                    signature_owner = INSTANCE_SIGNATURE_OWNER
                    logging.warning(
                        "No signature owner provided for %s. Using random signature owner %s.",
                        file_path,
                        signature_owner,
                    )

                # skip files that do not have an extension
                if file_ext is None or file_ext == "":
                    continue

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
    readme = f"# {arch.capitalize()} Secure Boot Defaults\n"

    # rewrite the first line of the information file to include the architecture
    readme += FIRMWARE_INFORMATION[1:]

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
            if 'arch' in file_dict:
                if file_dict.get("arch", arch) != arch:
                    continue
            else:
                # If the file does not have an architecture specified, it is assumed to be for all architectures
                pass

            if file_dict.get("url", None) is not None:
                readme += f"* {file_dict['path']}\n  * <{file_dict['url']}>\n"
            else:
                readme += f"* {file_dict['path']}\n"

    readme += "\n---\n\n"

    readme += LICENSE

    return bytes(readme, "utf-8")


def create_folder(directory: Path) -> None:
    """Creates a folder if it does not exist.

    Args:
        directory (Path): The path to the folder to create.
    """
    directory.mkdir(exist_ok=True, parents=True)
    directory.touch()

def create_binary(file: str, data: bytes) -> None:
    """Creates a binary file.

    Args:
        file (str): The path to the file to create.
        data (bytes): The data to write to the file.
    """
    file_path = Path(file)
    if file_path.exists():
        file_path.unlink()

    with open(file, "wb") as f:
        f.write(data)


def main() -> int:
    """Main entry point into the tool."""
    import argparse
    import pathlib

    try:
        import tomli as tomllib
    except Exception:
        import tomllib


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

        # First create the output folder if it does not exist
        output_folder = Path(args.output)
        create_folder(output_folder)

        template_name = os.path.basename(args.keystore).split('.')[0]

        # Build the default key binaries; filters on requested architectures in the configuration file.
        default_keys = build_default_keys(keystore)

        # Write the keys to the output directory and create a README.md file for each architecture.
        for key, value in default_keys.items():
            arch, variable = key

            arch_folder = output_folder / arch.capitalize()
            create_folder(arch_folder)

            template_folder = arch_folder / template_name
            create_folder(template_folder)

            # Create the firmware binaries for the default keys
            firmware_folder = template_folder / "Firmware"
            create_folder(firmware_folder)

            out_file = firmware_folder / f"{variable}.bin"
            create_binary(out_file, value)

            # Intentionally recreate the README.md file
            readme_path = firmware_folder / "README.md"
            create_binary(readme_path, create_readme(keystore, arch))

            # Create the imaging binaries for the default keys
            # These are special binaries that are used by Project Mu based firmware
            # to enable secure boot in the imaging process.
            imaging_folder = template_folder / "Imaging"
            create_folder(imaging_folder)

            out_file = imaging_folder / f"{variable}.bin"
            create_binary(out_file, _create_time_based_payload(value))

            # Intentionally recreate the README.md file
            imaging_readme_path = imaging_folder / "README.md"
            imaging_info = IMAGING_INFORMATION.encode()
            imaging_info += b"\n\n" + b"-" * 80 + b"\n\n"
            imaging_info += LICENSE.encode()
            create_binary(imaging_readme_path, imaging_info)

    logging.info("Default keys created successfully. See %s for details.", args.output)

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

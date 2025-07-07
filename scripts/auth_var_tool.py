"""Signs a variable in accordance with EFI_AUTHENTICATION_2.

Relevant RFC's
    * (PKCS #7: Cryptographic Message Syntax)[https://www.rfc-editor.org/rfc/rfc2315]
    * (Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
       (In particular To-be-signed Certificate))
       [https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2]
    * https://www.itu.int/ITU-T/formal-language/itu-t/x/x420/1999/PKCS7.html

# TODO:
    * Implement Certificate Verification (https://stackoverflow.com/questions/70654598/python-pkcs7-x509-chain-of-trust-with-cryptography)

pip requirements:
    pyasn1
    pyasn1_modules
    edk2toollib
    cryptography # Depends on having openssl installed
"""

import argparse
import logging
import os
import sys
import uuid
from getpass import getpass

from cryptography.hazmat.primitives.serialization import pkcs12
from edk2toollib.uefi.authenticated_variables_structure_support import (
    EfiVariableAuthentication2,
    EfiVariableAuthentication2Builder,
)

# from edk2toollib.uefi.uefi_multi_phase import EfiVariableAttributes

# Puts the script into debug mode, may be enabled via argparse
ENABLE_DEBUG = False

# Index into the certificate argument
CERTIFICATE_FILE_PATH = 0
CERTIFICATE_PASSWORD = 1


logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def sign_variable(args: argparse.Namespace) -> int:
    """Signs a variable in accordance with EFI_AUTHENTICATION_2 using the provided arguments.

    Parameters
    ----------
    args : argparse.Namespace
        The parsed command-line arguments required for signing the variable.

    Returns:
    -------
    int
        Status code (0 for success, non-zero for failure).
    """
    with open(args.data_file, 'rb') as f:
        data = f.read()

        builder = EfiVariableAuthentication2Builder(
            name=args.name,
            guid=args.guid,
            attributes=args.attributes,
            payload=data,
        )

        # Load the signing certificate from the PFX file
        with open(args.pfx_file, 'rb') as f:
            password = getpass("Enter the password for the PFX file: ").encode('utf-8')
            pkcs12_store = pkcs12.load_pkcs12(
                f.read(),
                password
            )

            builder.sign(pkcs12_store.cert.certificate, pkcs12_store.key)

            auth_var = builder.finalize()

            name = args.name
            logger.info(f"Signing variable: {name} with GUID: {args.guid}")
            output_file = os.path.join(args.output_dir, f"{name}.authvar.bin")

            with open(output_file, "wb") as f:
               f.write(auth_var.encode())

            logger.info(f"Signed variable saved to: {output_file}")

def describe_variable(args: argparse.Namespace) -> int:
    auth_var = None
    with open(args.signed_payload, 'rb') as f:
        auth_var = EfiVariableAuthentication2(decodefs=f)

    name = os.path.basename(args.signed_payload)
    output_file = os.path.join(args.output_dir, f"{name}.authvar.txt")

    with open(output_file, 'w') as f:
        auth_var.print(outfs=f)

    logger.info(f"Output: {output_file}")

    return 0


def typecheck_file_exists(filepath: str) -> str:
    """Checks if this is a valid filepath for argparse.

    :param filepath: filepath to check for existance

    :return: valid filepath
    """
    if not os.path.isfile(filepath):
        raise argparse.ArgumentTypeError(
            f"You sure this is a valid filepath? : {filepath}")

    return filepath

def setup_sign_parser(subparsers: argparse._SubParsersAction) -> argparse._SubParsersAction:
    """Sets up the sign parser.

    :param subparsers: - sub parser from argparse to add options to

    :returns: subparser
    """
    sign_parser = subparsers.add_parser(
        "sign", help="Signs variables using the command line"
    )
    sign_parser.set_defaults(function=sign_variable)

    sign_parser.add_argument(
        "name",
        help="UTF16 Formated Name of Variable"
    )

    sign_parser.add_argument(
        "guid", type=uuid.UUID,
        help="UUID of the namespace the variable belongs to. (Ex. 12345678-1234-1234-1234-123456789abc)"
    )

    sign_parser.add_argument(
        "attributes",
        help="Variable Attributes, AT is a required attribute (Ex. \"NV,BT,RT,AT\")"
    )

    sign_parser.add_argument(
        "data_file", type=typecheck_file_exists,
        help="Binary file of variable data. An empty file is accepted and will be used to clear the authenticated data"
    )

    sign_parser.add_argument(
        "pfx_file", type=typecheck_file_exists,
        help="Pkcs12 certificate to sign the authenticated data with (Cert.pfx)"
    )

    sign_parser.add_argument(
        "--output-dir", default="./",
        help="Output directory for the signed data"
    )

    return subparsers


def setup_describe_parser(subparsers):

    describe_parser = subparsers.add_parser(
        "describe", help="Parses Authenticated Variable 2 structures"
    )
    describe_parser.set_defaults(function=describe_variable)

    describe_parser.add_argument(
        "signed_payload", type=typecheck_file_exists,
        help="Signed payload to parse"
    )

    describe_parser.add_argument(
        "--output-dir", default="./",
        help="Output directory for the described data"
    )

    return subparsers


def parse_args():
    """Parses arguments from the command line
    """
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser.add_argument(
        "--debug", action='store_true', default=False,
        help="enables debug printing for deep inspection"
    )

    subparsers = setup_sign_parser(subparsers)
    subparsers = setup_describe_parser(subparsers)

    args = parser.parse_args()

    if not hasattr(args, "function"):
        parser.print_help(sys.stderr)
        sys.exit(1)

    global ENABLE_DEBUG
    ENABLE_DEBUG = args.debug

    if ENABLE_DEBUG:
        logger.setLevel(logging.DEBUG)

    return args


def main():
    args = parse_args()

    status_code = args.function(args)

    return sys.exit(status_code)


main()

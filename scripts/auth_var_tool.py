# @file
#
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""UEFI Authenticated Variable Tool for signing and formatting variables.

This tool provides three main commands:

1. format: Generates signable data and receipt files for external signing workflows
2. sign: Signs variables using PFX files or attaches pre-generated signatures
3. describe: Parses and describes existing signed variables

The tool supports both direct signing (using PFX files) and external signing
workflows (where signatures are generated outside this tool and then attached).

Relevant RFC's:
    * (PKCS #7: Cryptographic Message Syntax)[https://www.rfc-editor.org/rfc/rfc2315]
    * (Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
       (In particular To-be-signed Certificate))
       [https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2]
    * https://www.itu.int/ITU-T/formal-language/itu-t/x/x420/1999/PKCS7.html

Examples:
    # Generate signable data for external signing
    python auth_var_tool.py format MyVar 8be4df61-93ca-11d2-aa0d-00e098032b8c "NV,BS,RT,AT" mydata.bin

    # Sign directly with PFX file
    python auth_var_tool.py sign MyVar 8be4df61-93ca-11d2-aa0d-00e098032b8c "NV,BS,RT,AT" mydata.bin --pfx-file cert.pfx

    # Attach external signature using receipt
    python auth_var_tool.py sign --receipt-file MyVar.receipt.json --signature-file MyVar.bin.p7

    # Describe an existing signed variable
    python auth_var_tool.py describe signed_variable.bin
"""

import argparse
import datetime
import io
import json
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

# Puts the script into debug mode, may be enabled via argparse
ENABLE_DEBUG = False

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def format_variable(args: argparse.Namespace) -> int:
    """Formats a variable for signing by generating signable data and a receipt file.

    This command is used to prepare variables for external signing workflows
    by generating the signable data and a receipt that can be used later
    to attach a pre-generated signature.

    Parameters
    ----------
    args : argparse.Namespace
        The parsed command-line arguments required for formatting the variable.

    Returns:
    -------
    int
        Status code (0 for success, non-zero for failure).
    """
    # Validate required arguments
    required_args = ["name", "guid", "attributes", "data_file"]
    missing_args = [arg for arg in required_args if not getattr(args, arg, None)]
    if missing_args:
        logger.error(f"Missing required arguments: {', '.join(missing_args)}")
        return 1

    # Validate data file exists
    if not os.path.isfile(args.data_file):
        logger.error(f"Data file not found: {args.data_file}")
        return 1

    # Read the variable data
    with open(args.data_file, "rb") as f:
        data = f.read()

    # Create the authentication builder
    builder = EfiVariableAuthentication2Builder(
        name=args.name,
        guid=args.guid,
        attributes=args.attributes,
        payload=data,
    )

    # Generate signable data and receipt
    logger.info(f"Formatting variable '{args.name}' for external signing.")
    return _create_signable_data(builder, args)


def sign_variable(args: argparse.Namespace) -> int:
    """Signs a variable in accordance with EFI_AUTHENTICATION_2 using the provided arguments.

    This command handles two signing workflows:
    1. Direct signing with a PFX file
    2. Attaching a pre-generated signature (with or without receipt)

    Parameters
    ----------
    args : argparse.Namespace
        The parsed command-line arguments required for signing the variable.

    Returns:
    -------
    int
        Status code (0 for success, non-zero for failure).
    """
    # Handle receipt-based signature attachment (doesn't need variable args)
    if hasattr(args, "receipt_file") and args.receipt_file:
        if not args.signature_file:
            logger.error("--receipt-file requires --signature-file to be specified.")
            return 1
        if args.pfx_file:
            logger.error(
                "Cannot use --receipt-file with --pfx-file. Receipt mode is for attaching external signatures only."
            )
            return 1
        return _attach_signature_from_receipt(args)

    # Validate mutually exclusive options
    if args.pfx_file and args.signature_file:
        logger.error("Cannot specify both --pfx-file and --signature-file. Choose one signing method.")
        return 1

    # Validate that we have either PFX or signature file
    if not args.pfx_file and not args.signature_file:
        logger.error("Must specify either --pfx-file or --signature-file for signing.")
        logger.error("To generate signable data, use the 'format' command instead.")
        return 1

    # For non-receipt workflows, validate required arguments
    if not args.receipt_file:
        required_args = ["name", "guid", "attributes", "data_file"]
        missing_args = [arg for arg in required_args if not getattr(args, arg, None)]
        if missing_args:
            logger.error(f"Missing required arguments: {', '.join(missing_args)}")
            logger.error("These arguments are required unless using --receipt-file with --signature-file")
            return 1

        # Set timestamp if provided
        timestamp = datetime.datetime.now()
        if args.timestamp:
            try:
                # Parse ISO 8601 format timestamp
                if "T" in args.timestamp:
                    provided_time = datetime.datetime.fromisoformat(args.timestamp)
                else:
                    # Support date-only format, default to midnight
                    provided_time = datetime.datetime.fromisoformat(args.timestamp + "T00:00:00")

                # Ensure timezone-aware (default to UTC if not specified)
                if provided_time.tzinfo is None:
                    provided_time = provided_time.replace(tzinfo=datetime.timezone.utc)

                timestamp = provided_time.astimezone(datetime.timezone.utc)
                logger.info(f"Using provided timestamp: {timestamp.isoformat()}")

            except ValueError:
                logger.error(
                    f"Invalid timestamp format: {args.timestamp}. Expected ISO 8601 format (YYYY-MM-DDTHH:MM:SS)"
                )
                return 1

        # Validate data file exists
        if not os.path.isfile(args.data_file):
            logger.error(f"Data file not found: {args.data_file}")
            return 1

        # Read the variable data
        with open(args.data_file, "rb") as f:
            data = f.read()

        # Create the authentication builder
        builder = EfiVariableAuthentication2Builder(
            name=args.name, guid=args.guid, attributes=args.attributes, payload=data, efi_time=timestamp
        )

        # Handle case where PFX file is provided (sign the variable)
        if args.pfx_file:
            return _sign_with_pfx(builder, args)


def _create_signable_data(builder: EfiVariableAuthentication2Builder, args: argparse.Namespace) -> int:
    """Creates signable data when no PFX file is provided.

    Parameters
    ----------
    builder : EfiVariableAuthentication2Builder

    args : argparse.Namespace
        The parsed command-line arguments containing the output directory and variable name.

    Returns:
    -------
    int
        Status code (0 for success).
    """
    # Generate timestamp for the signing operation
    if args.timestamp:
        try:
            # Parse ISO 8601 format timestamp
            timestamp_str = args.timestamp if "T" in args.timestamp else args.timestamp + "T00:00:00"
            provided_time = datetime.datetime.fromisoformat(timestamp_str)

            # Ensure timezone-aware (default to UTC if not specified)
            if provided_time.tzinfo is None:
                provided_time = provided_time.replace(tzinfo=datetime.timezone.utc)

            signing_time = provided_time.astimezone(datetime.timezone.utc)
            logger.info(f"Using provided timestamp: {signing_time.isoformat()}")
        except ValueError:
            logger.error(f"Invalid timestamp format: {args.timestamp}. Expected ISO 8601 format (YYYY-MM-DDTHH:MM:SS)")
            return 1
    else:
        # Use current time
        signing_time = datetime.datetime.now(datetime.timezone.utc)
        logger.info(f"Using current timestamp: {signing_time.isoformat()}")

    # Create the signable data output file
    output_file = os.path.join(args.output_dir, f"{args.name}.signable.bin")
    with open(output_file, "wb") as f:
        f.write(builder.get_digest())

    # Create a receipt file with all the metadata needed for signature attachment
    receipt_data = {
        "variable_name": args.name,
        "variable_guid": str(args.guid),
        "variable_attributes": args.attributes,
        "data_file": os.path.abspath(args.data_file),
        "signing_timestamp": signing_time.isoformat(),
        "signable_data_file": os.path.abspath(output_file),
        "tool_version": "1.0",
        "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    receipt_file = os.path.join(args.output_dir, f"{args.name}.receipt.json")
    with open(receipt_file, "w") as f:
        json.dump(receipt_data, f, indent=2)

    logger.info(f"Signable data for {args.name} with GUID: {args.guid}")
    logger.info(f"Signable data saved to: {output_file}")
    logger.info(f"Receipt saved to: {receipt_file}")
    logger.info(f"To attach a signature later, use: --receipt-file {receipt_file}")
    return 0


def _sign_with_pfx(builder: EfiVariableAuthentication2Builder, args: argparse.Namespace) -> int:
    """Signs the variable using the provided PFX file.

    Parameters
    ----------
    builder : EfiVariableAuthentication2Builder

    args : argparse.Namespace
        The parsed command-line arguments containing the PFX file path and output directory.

    Returns:
    -------
    int
        Status code (0 for success).
    """
    # Load the signing certificate from the PFX file
    with open(args.pfx_file, "rb") as f:
        pfx_data = f.read()

    password = getpass("Enter the password for the PFX file: ").encode("utf-8")
    pkcs12_store = pkcs12.load_pkcs12(pfx_data, password)

    # Sign the variable
    builder.sign(pkcs12_store.cert.certificate, pkcs12_store.key)
    auth_var = builder.finalize()

    # Save the signed variable
    output_file = os.path.join(args.output_dir, f"{args.name}.authvar.bin")
    with open(output_file, "wb") as f:
        f.write(auth_var.encode())

    logger.info(f"Signed variable: {args.name} with GUID: {args.guid}")
    logger.info(f"Signed variable saved to: {output_file}")
    return 0


def _attach_signature_from_receipt(args: argparse.Namespace) -> int:
    """Attaches a pre-generated PKCS#7 signature using metadata from a receipt file.

    This function reads a receipt file generated during signable data creation
    and uses it to attach a signature with the correct metadata.

    Parameters
    ----------
    args : argparse.Namespace
        The parsed command-line arguments containing the receipt file path and signature file path.

    Returns:
    -------
    int
        Status code (0 for success).
    """
    # Read the receipt file
    try:
        with open(args.receipt_file, "r") as f:
            receipt = json.load(f)
    except FileNotFoundError:
        logger.error(f"Receipt file not found: {args.receipt_file}")
        return 1
    except json.JSONDecodeError as e:
        logger.error(f"Invalid receipt file format: {e}")
        return 1

    logger.info(f"Using receipt file: {args.receipt_file}")
    logger.info(f"Using pre-generated signature from: {args.signature_file}")

    # Validate required fields in receipt
    required_fields = ["variable_name", "variable_guid", "data_file", "signing_timestamp"]
    for field in required_fields:
        if field not in receipt:
            logger.error(f"Missing required field in receipt: {field}")
            return 1

    # Read the signature file (PKCS#7 signature)
    with open(args.signature_file, "rb") as f:
        signature_data = f.read()

    # Read the variable payload data from the path in the receipt
    try:
        with open(receipt["data_file"], "rb") as f:
            payload_data = f.read()
    except FileNotFoundError:
        logger.error(f"Variable data file not found: {receipt['data_file']}")
        logger.error("The data file path in the receipt may have changed since the receipt was created.")
        return 1

    # Parse the timestamp from the receipt
    try:
        signing_time = datetime.datetime.fromisoformat(receipt["signing_timestamp"])
        logger.info(f"Using timestamp from receipt: {signing_time.isoformat()}")
    except ValueError:
        logger.error(f"Invalid timestamp in receipt: {receipt['signing_timestamp']}")
        return 1

    # Create EfiVariableAuthentication2 structure
    auth_var = EfiVariableAuthentication2(time=signing_time)
    auth_var.auth_info.add_cert_data(signature_data)
    payload_stream = io.BytesIO(payload_data)
    auth_var.set_payload(payload_stream)

    # Encode the complete authenticated variable structure
    auth_var_data = auth_var.encode()

    # Save the signed variable
    output_file = os.path.join(args.output_dir, f"{receipt['variable_name']}.authvar.bin")
    with open(output_file, "wb") as f:
        f.write(auth_var_data)

    logger.info(f"Variable with attached signature: {receipt['variable_name']} with GUID: {receipt['variable_guid']}")
    logger.info(f"Signed variable saved to: {output_file}")
    return 0


def describe_variable(args: argparse.Namespace) -> int:
    """Parses and describes an authenticated variable structure.

    Parameters
    ----------
    args : argparse.Namespace
        The parsed command-line arguments containing the signed payload file path
        and output directory.

    Returns:
    -------
    int
        Status code (0 for success).
    """
    auth_var = None
    with open(args.signed_payload, "rb") as f:
        auth_var = EfiVariableAuthentication2(decodefs=f)

    name = os.path.basename(args.signed_payload)
    output_file = os.path.join(args.output_dir, f"{name}.authvar.txt")

    with open(output_file, "w") as f:
        auth_var.print(outfs=f)

    logger.info(f"Output: {output_file}")

    return 0


def typecheck_file_exists(filepath: str) -> str:
    """Checks if this is a valid filepath for argparse.

    :param filepath: filepath to check for existance

    :return: valid filepath
    """
    if not os.path.isfile(filepath):
        raise argparse.ArgumentTypeError(f"You sure this is a valid filepath? : {filepath}")

    return filepath


def setup_format_parser(subparsers: argparse._SubParsersAction) -> argparse._SubParsersAction:
    """Sets up the format parser for generating signable data and receipts.

    :param subparsers: - sub parser from argparse to add options to

    :returns: subparser
    """
    format_parser = subparsers.add_parser(
        "format", help="Formats variables for external signing by generating signable data and receipt files"
    )
    format_parser.set_defaults(function=format_variable)

    format_parser.add_argument("name", help="UTF16 Formatted Name of Variable")

    format_parser.add_argument(
        "guid",
        type=uuid.UUID,
        help="UUID of the namespace the variable belongs to. (Ex. 12345678-1234-1234-1234-123456789abc)",
    )

    format_parser.add_argument("attributes", help='Variable Attributes, AT is a required attribute (Ex. "NV,BS,RT,AT")')

    format_parser.add_argument(
        "data_file",
        help="Binary file of variable data. An empty file is accepted and will be used to clear the authenticated data",
    )

    format_parser.add_argument(
        "--timestamp",
        default=None,
        help="Timestamp to use for the authenticated variable in ISO 8601 format (YYYY-MM-DDTHH:MM:SS). "
        "If not provided, current UTC time will be used. Example: 2025-01-15T10:30:45",
    )

    format_parser.add_argument(
        "--output-dir", default="./", help="Output directory for the signable data and receipt file"
    )

    return subparsers


def setup_sign_parser(subparsers: argparse._SubParsersAction) -> argparse._SubParsersAction:
    """Sets up the sign parser for signing variables or attaching pre-generated signatures.

    :param subparsers: - sub parser from argparse to add options to

    :returns: subparser
    """
    sign_parser = subparsers.add_parser(
        "sign", help="Signs variables using PFX files or attaches pre-generated signatures"
    )
    sign_parser.set_defaults(function=sign_variable)

    sign_parser.add_argument(
        "name", nargs="?", help="UTF16 Formatted Name of Variable (not required when using --receipt-file)"
    )

    sign_parser.add_argument(
        "guid",
        nargs="?",
        type=uuid.UUID,
        help="UUID of the namespace the variable belongs to. (Ex. 12345678-1234-1234-1234-123456789abc)"
        " (not required when using --receipt-file)",
    )

    sign_parser.add_argument(
        "attributes",
        nargs="?",
        help="Variable Attributes, AT is a required attribute (Ex. \"NV,BS,RT,AT\")"
        " (not required when using --receipt-file)"
    )

    sign_parser.add_argument(
        "data_file",
        nargs="?",
        help="Binary file of variable data. An empty file is accepted and will be used to clear"
        "the authenticated data (not required when using --receipt-file)",
    )

    # Create mutually exclusive group for signing methods
    signing_group = sign_parser.add_mutually_exclusive_group(required=True)

    signing_group.add_argument(
        "--pfx-file",
        default=None,
        help="Pkcs12 certificate to sign the authenticated data with (Cert.pfx). "
        "Use this for direct signing with a private key.",
    )

    signing_group.add_argument(
        "--signature-file",
        default=None,
        type=typecheck_file_exists,
        help="Pre-generated PKCS#7 signature file (.bin.p7) to attach to the variable. "
        "Use this to attach signatures generated externally.",
    )

    sign_parser.add_argument(
        "--receipt-file",
        default=None,
        type=typecheck_file_exists,
        help="Receipt file (.receipt.json) generated during signable data creation. "
        "When used with --signature-file, all variable metadata will be read from the receipt, "
        "eliminating the need to specify name, GUID, attributes, data-file, and timestamp.",
    )

    sign_parser.add_argument(
        "--timestamp",
        default=None,
        help="Timestamp to use for the authenticated variable in ISO 8601 format (YYYY-MM-DDTHH:MM:SS). "
        "If not provided, current UTC time will be used. Only used when not using --receipt-file. "
        "Example: 2025-01-15T10:30:45",
    )

    sign_parser.add_argument("--output-dir", default="./", help="Output directory for the signed data")

    return subparsers


def setup_describe_parser(subparsers: argparse._SubParsersAction) -> argparse._SubParsersAction:
    """Sets up the describe parser.

    :param subparsers: - sub parser from argparse to add options to

    :returns: subparser
    """
    describe_parser = subparsers.add_parser("describe", help="Parses Authenticated Variable 2 structures")
    describe_parser.set_defaults(function=describe_variable)

    describe_parser.add_argument("signed_payload", type=typecheck_file_exists, help="Signed payload to parse")

    describe_parser.add_argument("--output-dir", default="./", help="Output directory for the described data")

    return subparsers


def parse_args() -> argparse.Namespace:
    """Parses arguments from the command line."""
    parser = argparse.ArgumentParser(
        description="UEFI Authenticated Variable Tool for signing and formatting variables"
    )
    subparsers = parser.add_subparsers(
        title="Available commands",
        description="Use these commands to work with UEFI authenticated variables",
        help="Command to execute",
    )

    parser.add_argument(
        "--debug", action="store_true", default=False, help="enables debug printing for deep inspection"
    )

    subparsers = setup_format_parser(subparsers)
    subparsers = setup_sign_parser(subparsers)
    subparsers = setup_describe_parser(subparsers)

    args = parser.parse_args()
    # Create output directory if it doesn't exist (after parsing args)
    if hasattr(args, 'output_dir') and args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)

    if not hasattr(args, "function"):
        parser.print_help(sys.stderr)
        sys.exit(1)

    global ENABLE_DEBUG
    ENABLE_DEBUG = args.debug

    if ENABLE_DEBUG:
        logger.setLevel(logging.DEBUG)

    return args


def main() -> None:
    """Entry point for the auth_var_tool script.

    Parses command-line arguments and executes the appropriate subcommand
    (sign or describe) based on user input.
    """
    args = parse_args()

    status_code = args.function(args)

    sys.exit(status_code)


if __name__ == "__main__":
    main()

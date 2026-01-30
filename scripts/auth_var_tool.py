# @file
#
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""UEFI Authenticated Variable Tool for signing and formatting variables.

This tool provides four main commands:

1. format: Generates signable data and receipt files for external signing workflows
2. sign: Signs variables using PFX files or attaches pre-generated signatures
3. verify: Verifies cryptographic signatures of authenticated variables
4. describe: Parses and describes existing signed variables

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

    # Verify a signed authenticated variable
    python auth_var_tool.py verify MyVar.authvar.bin MyVar 8be4df61-93ca-11d2-aa0d-00e098032b8c "NV,BS,RT,AT,AP" -v

    # Describe an existing signed variable
    python auth_var_tool.py describe signed_variable.bin
"""

import argparse
import datetime
import hashlib
import io
import json
import logging
import os
import re
import sys
import uuid
from getpass import getpass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from edk2toollib.uefi.authenticated_variables_structure_support import (
    EfiVariableAuthentication2,
    EfiVariableAuthentication2Builder,
)
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2315

# Puts the script into debug mode, may be enabled via argparse
ENABLE_DEBUG = False

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _parse_timestamp(timestamp_str: str = None) -> datetime.datetime:
    """Parse timestamp string into timezone-aware datetime object.

    Parameters
    ----------
    timestamp_str : str, optional
        ISO 8601 format timestamp string. If None, returns current UTC time.

    Returns:
    -------
    datetime.datetime
        Timezone-aware datetime object in UTC.

    Raises:
    ------
    ValueError
        If timestamp_str is not a valid ISO 8601 format.
    """
    if timestamp_str:
        # Parse ISO 8601 format timestamp
        timestamp_str = timestamp_str if "T" in timestamp_str else timestamp_str + "T00:00:00"
        provided_time = datetime.datetime.fromisoformat(timestamp_str)

        # Ensure timezone-aware (default to UTC if not specified)
        if provided_time.tzinfo is None:
            provided_time = provided_time.replace(tzinfo=datetime.timezone.utc)

        return provided_time.astimezone(datetime.timezone.utc)
    else:
        # Use current time
        return datetime.datetime.now(datetime.timezone.utc)


def _get_hash_algorithm_from_oid(oid: str) -> hashes.HashAlgorithm | None:
    """Map OID to cryptography hash algorithm."""
    oid_map = {
        '2.16.840.1.101.3.4.2.1': hashes.SHA256(),
        '2.16.840.1.101.3.4.2.2': hashes.SHA384(),
        '2.16.840.1.101.3.4.2.3': hashes.SHA512(),
        '1.3.14.3.2.26': hashes.SHA1(),
    }
    return oid_map.get(oid)


def _extract_certificates_from_pkcs7(pkcs7_data: bytes) -> list:
    """Extract X.509 certificates from PKCS7 data."""
    certificates = []
    try:
        # Try to decode as ContentInfo first
        try:
            content_info, _ = decoder.decode(pkcs7_data, asn1Spec=rfc2315.ContentInfo())
            signed_data, _ = decoder.decode(
                bytes(content_info['content']),
                asn1Spec=rfc2315.SignedData()
            )
        except Exception:
            # If that fails, try decoding directly as SignedData
            signed_data, _ = decoder.decode(pkcs7_data, asn1Spec=rfc2315.SignedData())

        # Extract certificates if present
        if signed_data['certificates'].hasValue():
            for cert_choice in signed_data['certificates']:
                cert_der = encoder.encode(cert_choice['certificate'])
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                certificates.append(cert)

    except Exception as e:
        logger.debug(f"Failed to extract certificates: {e}")

    return certificates


def _verify_pkcs7_signature(pkcs7_data: bytes, certificates: list, external_data: bytes) -> dict:
    """Verify PKCS7 detached signature against external data.

    Returns:
        dict: Verification results with 'verified' boolean and list of 'signers'
    """
    results = {
        'verified': False,
        'signers': [],
        'errors': []
    }

    try:
        # Decode PKCS7 structure
        try:
            content_info, _ = decoder.decode(pkcs7_data, asn1Spec=rfc2315.ContentInfo())
            signed_data, _ = decoder.decode(
                bytes(content_info['content']),
                asn1Spec=rfc2315.SignedData()
            )
        except Exception:
            signed_data, _ = decoder.decode(pkcs7_data, asn1Spec=rfc2315.SignedData())

        # Verify each signer
        for signer_idx, signer_info in enumerate(signed_data['signerInfos']):
            signer_result = {
                'index': signer_idx,
                'verified': False,
                'error': None
            }

            try:
                # Get digest algorithm
                digest_alg_oid = str(signer_info['digestAlgorithm']['algorithm'])
                hash_algorithm = _get_hash_algorithm_from_oid(digest_alg_oid)

                if not hash_algorithm:
                    signer_result['error'] = f"Unsupported digest algorithm: {digest_alg_oid}"
                    results['errors'].append(signer_result['error'])
                    results['signers'].append(signer_result)
                    continue

                # Get the encrypted digest (signature)
                encrypted_digest = bytes(signer_info['encryptedDigest'])

                # Find the signer's certificate
                serial_number = int(signer_info['issuerAndSerialNumber']['serialNumber'])
                signer_cert = None
                for cert in certificates:
                    if cert.serial_number == serial_number:
                        signer_cert = cert
                        break

                if not signer_cert:
                    signer_result['error'] = f"Signer certificate not found (serial: {serial_number})"
                    results['errors'].append(signer_result['error'])
                    results['signers'].append(signer_result)
                    continue

                # Determine what data to verify
                if signer_info['authenticatedAttributes'].hasValue():
                    # With authenticated attributes, sign the attributes
                    authenticated_attrs = signer_info['authenticatedAttributes']
                    attrs_der = encoder.encode(authenticated_attrs)
                    # Replace IMPLICIT tag [0] (0xA0) with SET OF tag (0x31)
                    if attrs_der[0:1] == b'\xa0':
                        attrs_der = b'\x31' + attrs_der[1:]
                    data_to_verify = attrs_der
                else:
                    # No authenticated attributes - verify external data directly
                    data_to_verify = external_data

                # Verify signature
                public_key = signer_cert.public_key()

                if isinstance(public_key, rsa.RSAPublicKey):
                    public_key.verify(
                        encrypted_digest,
                        data_to_verify,
                        padding.PKCS1v15(),
                        hash_algorithm
                    )
                    signer_result['verified'] = True
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    public_key.verify(
                        encrypted_digest,
                        data_to_verify,
                        ec.ECDSA(hash_algorithm)
                    )
                    signer_result['verified'] = True
                else:
                    signer_result['error'] = f"Unsupported key type: {type(public_key)}"
                    results['errors'].append(signer_result['error'])

            except InvalidSignature:
                signer_result['error'] = "Signature verification failed - invalid signature"
                results['errors'].append(signer_result['error'])
            except Exception as e:
                signer_result['error'] = f"Verification error: {str(e)}"
                results['errors'].append(signer_result['error'])

            results['signers'].append(signer_result)

        # Overall verification passes if all signers verified
        results['verified'] = all(s['verified'] for s in results['signers']) and len(results['signers']) > 0

    except Exception as e:
        results['errors'].append(f"PKCS7 parsing error: {str(e)}")

    return results


def verify_variable(args: argparse.Namespace) -> int:
    """Verifies the cryptographic signature of an authenticated variable.

    This command validates that:
    1. The PKCS7 signature structure is valid
    2. The signature cryptographically verifies against the signable data
    3. The signing certificate is present in the signature

    Parameters
    ----------
    args : argparse.Namespace
        Command-line arguments including:
        - authvar_file: Path to the signed authenticated variable file
        - var_name: Variable name used during signing
        - var_guid: Variable GUID used during signing
        - attributes: Variable attributes used during signing
        - verbose: Enable detailed output

    Returns:
    -------
    int
        0 if verification succeeds, 1 if verification fails
    """
    try:
        # Parse the authenticated variable
        logger.info(f"Verifying authenticated variable: {args.authvar_file}")

        with open(args.authvar_file, 'rb') as f:
            auth_var = EfiVariableAuthentication2(decodefs=f)

        # Reconstruct the signable data using the builder
        signing_time = auth_var.time.get_datetime()
        builder = EfiVariableAuthentication2Builder(
            name=args.var_name,
            guid=uuid.UUID(args.var_guid),
            attributes=args.attributes,
            payload=auth_var.payload,
            efi_time=signing_time
        )
        signable_data = builder.get_digest()

        if args.verbose:
            logger.info(f"Variable Name: {args.var_name}")
            logger.info(f"Variable GUID: {args.var_guid}")
            logger.info(f"Attributes: {args.attributes}")
            logger.info(f"Signing Time: {signing_time}")
            logger.info(f"Payload Size: {len(auth_var.payload)} bytes")
            logger.info(f"Signable Data SHA256: {hashlib.sha256(signable_data).hexdigest()}")

        # Extract PKCS7 signature (cert_data from edk2toollib is the PKCS7 data)
        pkcs7_data = auth_var.auth_info.cert_data

        # Extract certificates
        certificates = _extract_certificates_from_pkcs7(pkcs7_data)

        if args.verbose:
            logger.info(f"\nCertificates found: {len(certificates)}")
            for i, cert in enumerate(certificates, 1):
                logger.info(f"  Certificate {i}:")
                logger.info(f"    Subject: {cert.subject.rfc4514_string()}")
                logger.info(f"    Issuer: {cert.issuer.rfc4514_string()}")
                logger.info(f"    Valid: {cert.not_valid_before_utc} to {cert.not_valid_after_utc}")

        # Verify the signature
        verification_result = _verify_pkcs7_signature(pkcs7_data, certificates, signable_data)

        # Display results
        if args.verbose:
            logger.info("")
            logger.info("Signature Verification Results:")
            for signer in verification_result['signers']:
                logger.info(f"  Signer {signer['index'] + 1}:")
                if signer['verified']:
                    logger.info("    Status: VERIFIED")
                else:
                    logger.info("    Status: FAILED")
                    if signer['error']:
                        logger.info(f"    Error: {signer['error']}")

        if verification_result['verified']:
            logger.info("[+] Authenticated variable signature is VALID")
            return 0
        else:
            logger.error("[-] Authenticated variable signature verification FAILED")
            for error in verification_result['errors']:
                logger.error(f"  - {error}")
            return 1

    except Exception as e:
        logger.error(f"Failed to verify authenticated variable: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


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

    # Parse timestamp using the helper function
    try:
        signing_time = _parse_timestamp(args.timestamp)
        logger.info(f"Using timestamp: {signing_time.isoformat()}")
    except ValueError:
        logger.error(f"Invalid timestamp format: {args.timestamp}. Expected ISO 8601 format (YYYY-MM-DDTHH:MM:SS)")
        return 1

    # Create the authentication builder with the correct timestamp
    builder = EfiVariableAuthentication2Builder(
        name=args.name,
        guid=args.guid,
        attributes=args.attributes,
        payload=data,
        efi_time=signing_time,
    )

    # Generate signable data and receipt
    logger.info(f"Formatting variable '{args.name}' for external signing.")
    return _create_signable_data(builder, args, signing_time)


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

        # Parse timestamp using the helper function
        try:
            timestamp = _parse_timestamp(args.timestamp)
            logger.info(f"Using timestamp: {timestamp.isoformat()}")
        except ValueError:
            logger.error(f"Invalid timestamp format: {args.timestamp}. Expected ISO 8601 format (YYYY-MM-DDTHH:MM:SS)")
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


def _create_signable_data(
    builder: EfiVariableAuthentication2Builder,
    args: argparse.Namespace,
    signing_time: datetime.datetime = None
) -> int:
    """Creates signable data when no PFX file is provided.

    Parameters
    ----------
    builder : EfiVariableAuthentication2Builder

    args : argparse.Namespace
        The parsed command-line arguments containing the output directory and variable name.

    signing_time : datetime.datetime, optional
        The timestamp to use for signing. If None, current time is used.

    Returns:
    -------
    int
        Status code (0 for success).
    """
    # Create the signable data output file
    output_file = os.path.join(args.output_dir, f"{args.name}.signable.bin")
    with open(output_file, "wb") as f:
        f.write(builder.get_digest())

    # signing_time should always be provided by the caller
    assert signing_time is not None, "signing_time must be provided to _create_signable_data"

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


def _convert_hex_strings_to_readable(content: str) -> str:
    """Convert hex-encoded strings in describe output to human-readable format.

    This function searches for patterns like "value=0x131a..." in the content
    and attempts to decode them as UTF-8 strings. Common encodings in certificates
    include PrintableString (0x13), UTF8String (0x0c), and IA5String (0x16).

    Parameters
    ----------
    content : str
        The original text content from auth_var.print()

    Returns:
    -------
    str
        The content with hex strings converted to readable format where possible
    """

    # Pattern to match hex value lines like "         value=0x131a444f204e4f54..."
    pattern = r'([ ]*value=)(0x[0-9a-fA-F]+)'

    def decode_hex_value(match: 're.Match[str]') -> str:
        indent = match.group(1)
        hex_string = match.group(2)

        try:
            # Remove "0x" prefix and convert to bytes
            hex_bytes = bytes.fromhex(hex_string[2:])

            # Check if this looks like an ASN.1 encoded string
            # Common prefixes: 0x13 (PrintableString), 0x0c (UTF8String), 0x16 (IA5String)
            if len(hex_bytes) >= 2 and hex_bytes[0] in [0x13, 0x0c, 0x16]:
                # Second byte is the length
                length = hex_bytes[1]
                if len(hex_bytes) >= 2 + length:
                    # Extract the string content
                    string_data = hex_bytes[2:2+length]
                    try:
                        # Attempt to decode as UTF-8
                        decoded = string_data.decode('utf-8')
                        # Only replace if it looks like printable text
                        if decoded.isprintable() or all(c in '\t\n\r' or c.isprintable() for c in decoded):
                            return f'{indent}{hex_string} ("{decoded}")'
                    except (UnicodeDecodeError, AttributeError):
                        # Decoding failed; ignore and try the next decoding strategy.
                        pass

            # If it's not ASN.1 encoded, try direct UTF-8 decode
            # (in case it's just raw string data)
            try:
                decoded = hex_bytes.decode('utf-8')
                if decoded.isprintable() or all(c in '\t\n\r' or c.isprintable() for c in decoded):
                    return f'{indent}{hex_string} ("{decoded}")'
            except UnicodeDecodeError:
                pass

        except (ValueError, IndexError) as e:
            # Failed to decode hex string as ASN.1 or UTF-8; this is expected for some values.
            logging.debug(f"Failed to decode hex string '{hex_string}': {e}")

        # If decoding fails, return original
        return match.group(0)

    return re.sub(pattern, decode_hex_value, content)


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

    # First write to a buffer to capture the output
    buffer = io.StringIO()
    auth_var.print(outfs=buffer)

    # Get the content and convert hex strings to readable format
    content = buffer.getvalue()
    readable_content = _convert_hex_strings_to_readable(content)

    # Write the converted content to the output file
    with open(output_file, "w") as f:
        f.write(readable_content)

    payload_hash = hashlib.sha256(auth_var.payload).hexdigest()
    logger.info(f"Payload SHA256: {payload_hash}")
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


def setup_verify_parser(subparsers: argparse._SubParsersAction) -> argparse._SubParsersAction:
    """Sets up the verify parser.

    :param subparsers: - sub parser from argparse to add options to

    :returns: subparser
    """
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verifies the cryptographic signature of an authenticated variable"
    )
    verify_parser.set_defaults(function=verify_variable)

    verify_parser.add_argument(
        "authvar_file",
        type=typecheck_file_exists,
        help="Path to the signed authenticated variable file (.authvar.bin)"
    )

    verify_parser.add_argument(
        "var_name",
        help="Variable name that was used during signing (e.g., 'KEK', 'db', 'PK')"
    )

    verify_parser.add_argument(
        "var_guid",
        help="Variable GUID that was used during signing (e.g., '8be4df61-93ca-11d2-aa0d-00e098032b8c')"
    )

    verify_parser.add_argument(
        "attributes",
        help="Comma-separated list of attributes used during signing (e.g., 'NV,BS,RT,AT,AP')"
    )

    verify_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output with detailed verification information"
    )

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

    setup_format_parser(subparsers)
    setup_sign_parser(subparsers)
    setup_describe_parser(subparsers)
    setup_verify_parser(subparsers)

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

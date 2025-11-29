# @file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This script extracts the signing certificate from an authenticated file.

It processes the file, decodes the PKCS#7 signature, and retrieves the
signing certificate, saving it as a DER-encoded file or JSON mapping.
"""

import argparse
import json
import logging
import os
from hashlib import sha1, sha256
from pathlib import Path

from cryptography.x509 import load_der_x509_certificate
from edk2toollib.uefi.authenticated_variables_structure_support import EfiVariableAuthentication2
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1_modules import rfc2315

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def pkcs7_get_signed_data_structure(signature: rfc2315.ContentInfo) -> rfc2315.SignedData:
    """Extract and decode the SignedData structure from a PKCS#7 signature."""
    content_info = None
    signed_data = None
    try:
        content_info, _ = der_decode(signature, asn1Spec=rfc2315.ContentInfo())

        content_type = content_info.getComponentByName("contentType")
        if content_type != rfc2315.signedData:
            raise ValueError("This wasn't a signed data structure?")

        signed_data, _ = der_decode(content_info.getComponentByName("content"), asn1Spec=rfc2315.SignedData())

    except Exception:
        try:
            signed_data, _ = der_decode(signature, asn1Spec=rfc2315.SignedData())
        except Exception as e:
            logging.error(f"Failed to decode the signature as a SignedData structure: {e}")
            return None

    return der_encode(signed_data)


def get_signing_certificate(signed_data: bytes) -> bytes:
    """Extract the signing certificate from a SignedData structure."""
    signed_data, _ = der_decode(signed_data, asn1Spec=rfc2315.SignedData())

    certificates = signed_data.getComponentByName("certificates")
    if certificates is None:
        raise ValueError("No certificates found in the SignedData structure")

    signer_infos = signed_data.getComponentByName("signerInfos")
    if not signer_infos:
        raise ValueError("No signer information found in the SignedData structure")

    signer_info = signer_infos[0]

    issuer_and_serial = signer_info.getComponentByName("issuerAndSerialNumber")
    serial_number = issuer_and_serial.getComponentByName("serialNumber")

    for cert in certificates:
        cert_der = der_encode(cert)
        certificate = load_der_x509_certificate(cert_der)

        cert_serial_number = certificate.serial_number

        if cert_serial_number == serial_number:
            return cert_der

    raise ValueError("No matching certificate found for the signer")


def process_auth_file(file_path: str) -> tuple[bytes, bytes, bytes]:
    """Process an authenticated file to extract the signing certificate.

    Returns:
        Tuple of (certificate_der, sha1_thumbprint, sha256_thumbprint)
    """
    auth_var = None
    certificate = None
    with open(file_path, "rb") as f:
        auth_var = EfiVariableAuthentication2(decodefs=f)
        auth_info = auth_var.auth_info
        content_info = auth_info.cert_data
        signed_data = pkcs7_get_signed_data_structure(content_info)
        certificate = get_signing_certificate(signed_data)

    if certificate is None:
        raise ValueError("No signing certificate found in the file")

    sha1_thumbprint = sha1(certificate).digest()
    sha256_thumbprint = sha256(certificate).digest()

    return certificate, sha1_thumbprint, sha256_thumbprint


def get_certificate_info(certificate_der: bytes) -> dict:
    """Extract certificate information for JSON output."""
    cert = load_der_x509_certificate(certificate_der)

    # Convert serial number to hexadecimal string (matching Windows certutil format)
    # The serial number in X.509 certificates is an ASN.1 INTEGER, which is always
    # stored as a signed value. However, RFC 5280 specifies it should be positive.
    # Some certificates may have the high bit set, causing Python's cryptography
    # library to interpret them as negative. We extract the actual bytes and
    # interpret them as unsigned to match the certificate's actual serial number.
    serial_number = cert.serial_number
    if serial_number < 0:
        # Get the byte length needed to represent the absolute value
        byte_length = (serial_number.bit_length() + 7) // 8
        # Convert to unsigned by interpreting as two's complement
        serial_number = serial_number % (1 << (byte_length * 8))

    serial_hex = format(serial_number, 'x')

    issued_to = cert.subject.rfc4514_string()
    issued_by = cert.issuer.rfc4514_string()

    return {
        "serial_number": serial_hex,
        "issued_to": issued_to,
        "issued_by": issued_by
    }


def process_single_file(file_path: str, save_der: bool = True) -> None:
    """Process a single authenticated file and save the certificate."""
    try:
        certificate, sha1_thumb, sha256_thumb = process_auth_file(file_path)
        logging.info("Signing certificate extracted successfully.")

        if save_der:
            certificate_file = file_path + "_signing_certificate.der"
            with open(certificate_file, "wb") as cert_file:
                cert_file.write(certificate)
            logging.info(f"Certificate saved as '{certificate_file}'")

        logging.info(f"SHA1 thumbprint: {sha1_thumb.hex()}")
        logging.info(f"SHA256 thumbprint: {sha256_thumb.hex()}")

        # Print certificate information
        cert_info = get_certificate_info(certificate)
        logging.info("")
        logging.info("Certificate Information:")
        logging.info(f"  Serial Number: {cert_info['serial_number']}")
        logging.info(f"  Issued To: {cert_info['issued_to']}")
        logging.info(f"  Issued By: {cert_info['issued_by']}")

    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}")


def process_directory(directory_path: str, output_json: str) -> None:
    """Process all .bin files in a directory and create a JSON mapping."""
    directory = Path(directory_path)

    if not directory.is_dir():
        raise ValueError(f"'{directory_path}' is not a valid directory")

    results = {}

    # Find all .bin files recursively
    bin_files = list(directory.rglob("*.bin"))
    logging.info(f"Found {len(bin_files)} .bin files to process")

    for bin_file in bin_files:
        try:
            certificate, sha1_thumb, _ = process_auth_file(str(bin_file))

            # Get relative path from the directory root
            relative_path = bin_file.relative_to(directory)

            # Use SHA1 thumbprint as key (matching kek_update_map.json format)
            key = sha1_thumb.hex()

            cert_info = get_certificate_info(certificate)

            results[key] = {
                "KEKUpdate": relative_path.as_posix(),
                "Certificate": cert_info
            }

            logging.info(f"Processed: {relative_path}")

        except Exception as e:
            try:
                rel_path = bin_file.relative_to(directory)
                logging.warning(f"Failed to process {rel_path}: {e}")
            except ValueError:
                logging.warning(f"Failed to process {bin_file}: {e}")
            continue

    # Write results to JSON file with Unicode characters preserved
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    logging.info(f"JSON mapping saved to '{output_json}'")
    logging.info(f"Successfully processed {len(results)} files")


def main() -> None:
    """Main function to extract the signing certificate from an authenticated file.

    This function parses command-line arguments, processes the specified file or directory,
    and saves the extracted signing certificate to a file or JSON mapping.
    """
    parser = argparse.ArgumentParser(
        description="Extract signing certificate from authenticated file(s).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process a single file
  %(prog)s file.bin

  # Process a directory and create JSON mapping
  %(prog)s --directory ./KEK --output kek_map.json
        """
    )
    parser.add_argument("path", nargs="?", help="Path to the authenticated file")
    parser.add_argument("--directory", "-d", help="Process all .bin files in directory")
    parser.add_argument("--output", "-o", help="Output JSON file for directory mode", default=None)
    args = parser.parse_args()

    if args.directory:
        # Directory mode

        if args.output is None:
            args.output = os.path.join(args.directory, "kek_update_map.json")

        try:
            process_directory(args.directory, args.output)
        except Exception as e:
            logging.error(f"Error: {e}")
    elif args.path:
        # Single file mode
        try:
            process_single_file(args.path)
        except Exception as e:
            logging.error(f"Error: {e}")
    else:
        parser.error("Either provide a file path or use --directory option")


if __name__ == "__main__":
    main()

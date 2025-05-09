# @file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This script extracts the signing certificate from an authenticated file.

It processes the file, decodes the PKCS#7 signature, and retrieves the
signing certificate, saving it as a DER-encoded file.
"""

import argparse
import logging
from hashlib import sha1, sha256

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
            logging.error("Failed to decode the signature as a SignedData structure: %s", str(e))
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

        # Convert the serial number to a positive 128-bit integer
        cert_serial_number = cert_serial_number & ((1 << 128) - 1)

        if cert_serial_number == serial_number:
            return cert_der

    raise ValueError("No matching certificate found for the signer")


def process_auth_file(file_path: str) -> bytes:
    """Process an authenticated file to extract the signing certificate."""
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

    return certificate


def main() -> None:
    """Main function to extract the signing certificate from an authenticated file.

    This function parses command-line arguments, processes the specified file,
    and saves the extracted signing certificate to a file.
    """
    parser = argparse.ArgumentParser(description="Extract signing certificate from an authenticated file.")
    parser.add_argument("file", help="Path to the authenticated file")
    args = parser.parse_args()

    try:
        certificate = process_auth_file(args.file)
        logging.info("Signing certificate extracted successfully.")

        certificate_file = args.file + "_signing_certificate.der"
        with open(certificate_file, "wb") as cert_file:
            cert_file.write(certificate)

        logging.info("SHA1 thumbprint %s", sha1(certificate).hexdigest())
        logging.info("SHA256 thumbprint %s", sha256(certificate).hexdigest())
        logging.info("Certificate saved as '%s'", certificate_file)
    except Exception as e:
        logging.error("Error: %s", e)


if __name__ == "__main__":
    main()

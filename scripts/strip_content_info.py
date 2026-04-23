# @file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Strip PKCS#7 ContentInfo wrappers from EFI auth variable signatures.

Some tooling expects the certificate payload to be raw SignedData instead of a
ContentInfo wrapper. This script rewrites an authenticated variable payload by
replacing cert_data with DER-encoded SignedData.
"""

import argparse
import logging
import pathlib
import sys

from edk2toollib.uefi.authenticated_variables_structure_support import EfiVariableAuthentication2
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1_modules import rfc2315


def pkcs7_get_signed_data_structure(signature: bytes) -> bytes:
    """Return DER-encoded SignedData from a DER PKCS#7 payload.

    The input may be either ContentInfo(signedData) or SignedData directly.
    """
    try:
        content_info, _ = der_decode(signature, asn1Spec=rfc2315.ContentInfo())
        content_type = content_info.getComponentByName("contentType")
        if content_type != rfc2315.signedData:
            raise ValueError("PKCS#7 payload is not signedData content")

        signed_data, _ = der_decode(
            content_info.getComponentByName("content"),
            asn1Spec=rfc2315.SignedData(),
        )
        logging.info("Found PKCS#7 ContentInfo(signedData); stripping ContentInfo wrapper")
        return der_encode(signed_data)
    except Exception as content_info_error:
        logging.debug("ContentInfo decode failed: %s", content_info_error)
        logging.info("Input does not decode as ContentInfo; trying SignedData")

    try:
        signed_data, _ = der_decode(signature, asn1Spec=rfc2315.SignedData())
        logging.info("Input already decodes as SignedData")
        return der_encode(signed_data)
    except Exception as signed_data_error:
        raise ValueError(
            "Signature is neither ContentInfo(signedData) nor SignedData"
        ) from signed_data_error


def strip_content_info(signed_payload: pathlib.Path) -> pathlib.Path:
    """Rewrite signed_payload with cert_data set to raw SignedData.

    Returns the path of the rewritten output file.
    """
    with open(signed_payload, "rb") as in_file:
        auth_var = EfiVariableAuthentication2(decodefs=in_file)

    # cert_data contains the PKCS#7 blob carried inside WIN_CERTIFICATE_UEFI_GUID.
    signed_data = pkcs7_get_signed_data_structure(auth_var.auth_info.cert_data)
    auth_var.auth_info.cert_data = signed_data

    out_path = signed_payload.with_name(signed_payload.name + ".stripped")
    with open(out_path, "wb") as out_file:
        out_file.write(auth_var.encode())

    logging.info("Stripped signed payload written to: %s", out_path)
    return out_path


def main() -> int:
    """Parse CLI arguments and strip ContentInfo from the provided payload."""
    parser = argparse.ArgumentParser(description="Strip ContentInfo from signed payload")
    parser.add_argument("signed_payload", type=pathlib.Path, help="Path to signed payload")
    args = parser.parse_args()

    try:
        strip_content_info(args.signed_payload)
    except Exception as error:
        logging.error("Failed to strip ContentInfo: %s", error)
        return 1

    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    sys.exit(main())

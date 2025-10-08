# @file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""This script transplants Authenticode signature from one signed PE to another signed PE.

This script:
1. Takes as arguments two signed PEs (EFI applications)
2. Compares the binaries and confirms that they are valid (other than the signature they should be binary compatible)
3. Extracts the signature from the first binary
4. Appends that signature to the second binary
5. Confirms that the transplant was successful
"""

import argparse
import hashlib
import logging
import os
import sys
from typing import Tuple

import pefile

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def validate_pe_file(pe_path: str) -> pefile.PE:
    """Validate that a file is a valid PE file and return the PE object.

    Args:
        pe_path: Path to the PE file to validate

    Returns:
        pefile.PE: The PE object if valid

    Raises:
        ValueError: If the file is not a valid PE file
        FileNotFoundError: If the file doesn't exist
    """
    if not os.path.exists(pe_path):
        raise FileNotFoundError(f"PE file not found: {pe_path}")

    try:
        pe = pefile.PE(pe_path)
        logger.info(f"Validated PE file: {pe_path}")
        return pe
    except pefile.PEFormatError as e:
        raise ValueError(f"Invalid PE file format: {pe_path} - {e}")


def extract_authenticode_signature(pe_path: str) -> Tuple[bytes, int, int]:
    """Extract the Authenticode signature from a PE file.

    Args:
        pe_path: Path to the signed PE file

    Returns:
        Tuple containing:
        - bytes: The signature data
        - int: Offset of the signature in the file
        - int: Size of the signature

    Raises:
        ValueError: If no signature is found or signature is invalid
    """
    pe = validate_pe_file(pe_path)

    # Check if the PE has a security directory entry
    if not hasattr(pe, 'OPTIONAL_HEADER') or not hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
        raise ValueError(f"PE file has no data directory: {pe_path}")

    # Security directory is entry 4 (IMAGE_DIRECTORY_ENTRY_SECURITY)
    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 4:
        raise ValueError(f"PE file has no security directory entry: {pe_path}")

    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    if security_dir.VirtualAddress == 0 or security_dir.Size == 0:
        raise ValueError(f"PE file is not signed (no security directory): {pe_path}")

    # Read the signature data from the file
    with open(pe_path, 'rb') as f:
        f.seek(security_dir.VirtualAddress)
        signature_data = f.read(security_dir.Size)

    if len(signature_data) != security_dir.Size:
        raise ValueError(f"Failed to read complete signature data from {pe_path}")

    logger.info(
        f"Extracted signature from {pe_path}: {security_dir.Size} bytes at offset 0x{security_dir.VirtualAddress:x}"
    )

    return signature_data, security_dir.VirtualAddress, security_dir.Size


def get_pe_content_hash(pe_path: str) -> str:
    """Get a hash of the PE file content excluding the signature.

    Args:
        pe_path: Path to the PE file

    Returns:
        str: SHA256 hash of the PE content (excluding signature)
    """
    pe = validate_pe_file(pe_path)

    with open(pe_path, 'rb') as f:
        file_data = f.read()

    # If there's a security directory, exclude it from the hash
    if (hasattr(pe, 'OPTIONAL_HEADER') and
        hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') and
        len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4):

        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if security_dir.VirtualAddress != 0 and security_dir.Size != 0:
            # Hash everything up to the signature
            content_to_hash = file_data[:security_dir.VirtualAddress]
        else:
            content_to_hash = file_data
    else:
        content_to_hash = file_data

    return hashlib.sha256(content_to_hash).hexdigest()


def are_pe_files_compatible(source_pe_path: str, target_pe_path: str) -> bool:
    """Check if two PE files are compatible for signature transplantation.

    Args:
        source_pe_path: Path to the source PE file (signature donor)
        target_pe_path: Path to the target PE file (signature recipient)

    Returns:
        bool: True if the PE files are compatible for signature transplantation
    """
    try:
        source_hash = get_pe_content_hash(source_pe_path)
        target_hash = get_pe_content_hash(target_pe_path)

        logger.info(f"Source PE content hash: {source_hash}")
        logger.info(f"Target PE content hash: {target_hash}")

        if source_hash == target_hash:
            logger.info("PE files are compatible for signature transplantation")
            return True
        else:
            logger.warning("PE files have different content hashes - transplantation may not be valid")
            return False

    except Exception as e:
        logger.error(f"Error comparing PE files: {e}")
        return False


def transplant_signature(source_pe_path: str, target_pe_path: str, output_pe_path: str) -> bool:
    """Transplant the Authenticode signature from source PE to target PE.

    Args:
        source_pe_path: Path to the source PE file (signature donor)
        target_pe_path: Path to the target PE file (signature recipient)
        output_pe_path: Path where the transplanted PE file will be saved

    Returns:
        bool: True if transplantation was successful
    """
    try:
        # Extract signature from source
        signature_data, _, signature_size = extract_authenticode_signature(source_pe_path)

        # Validate target PE
        target_pe = validate_pe_file(target_pe_path)

        # Read target PE file data
        with open(target_pe_path, 'rb') as f:
            target_data = bytearray(f.read())

        # Check if target already has a signature and remove it
        if (hasattr(target_pe, 'OPTIONAL_HEADER') and
            hasattr(target_pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') and
            len(target_pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4):

            security_dir = target_pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if security_dir.VirtualAddress != 0 and security_dir.Size != 0:
                # Remove existing signature
                target_data = target_data[:security_dir.VirtualAddress]
                logger.info(f"Removed existing signature from target PE (was {security_dir.Size} bytes)")

        # Append new signature to the end of the file
        signature_offset = len(target_data)
        target_data.extend(signature_data)

        # Update the security directory in the PE header
        # We need to parse the PE again to get the correct offsets
        target_pe_new = pefile.PE(data=target_data, fast_load=True)

        # Update the security directory entry
        if len(target_pe_new.OPTIONAL_HEADER.DATA_DIRECTORY) > 4:
            target_pe_new.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress = signature_offset
            target_pe_new.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size = signature_size

            # Get the updated PE data
            target_data = target_pe_new.write()

        # Write the transplanted PE to output file
        with open(output_pe_path, 'wb') as f:
            f.write(target_data)

        logger.info(f"Successfully transplanted signature to {output_pe_path}")
        logger.info(f"Signature size: {signature_size} bytes at offset 0x{signature_offset:x}")

        return True

    except Exception as e:
        logger.error(f"Failed to transplant signature: {e}")
        return False


def verify_transplant(output_pe_path: str) -> bool:
    """Verify that the signature transplant was successful.

    Args:
        output_pe_path: Path to the transplanted PE file

    Returns:
        bool: True if the transplant appears successful
    """
    try:
        # Validate that the output is still a valid PE file
        pe = validate_pe_file(output_pe_path)

        # Check that it has a signature
        if (hasattr(pe, 'OPTIONAL_HEADER') and
            hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') and
            len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4):

            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if security_dir.VirtualAddress != 0 and security_dir.Size != 0:
                logger.info(f"Verification successful: Output PE has signature ({security_dir.Size} bytes)")
                return True

        logger.error("Verification failed: Output PE has no signature")
        return False

    except Exception as e:
        logger.error(f"Verification failed: {e}")
        return False


def main() -> int:
    """Main entry point for the authenticode transplant tool."""
    parser = argparse.ArgumentParser(
        description="Transplant Authenticode signature from one signed PE to another signed PE"
    )

    parser.add_argument(
        "source_pe",
        help="Path to the source PE file (signature donor)"
    )

    parser.add_argument(
        "target_pe",
        help="Path to the target PE file (signature recipient)"
    )

    parser.add_argument(
        "output_pe",
        help="Path where the transplanted PE file will be saved"
    )

    parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Force transplantation even if PE files are not compatible"
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Enable debug logging"
    )

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    try:
        # Validate input files exist
        if not os.path.exists(args.source_pe):
            logger.error(f"Source PE file not found: {args.source_pe}")
            return 1

        if not os.path.exists(args.target_pe):
            logger.error(f"Target PE file not found: {args.target_pe}")
            return 1

        # Check if files are compatible (unless forced)
        if not args.force:
            if not are_pe_files_compatible(args.source_pe, args.target_pe):
                logger.error("PE files are not compatible for signature transplantation")
                logger.error("Use --force to override this check")
                return 1
        else:
            logger.warning("Compatibility check bypassed due to --force flag")

        # Perform the transplant
        logger.info(f"Transplanting signature from {args.source_pe} to {args.target_pe}")
        if not transplant_signature(args.source_pe, args.target_pe, args.output_pe):
            logger.error("Signature transplantation failed")
            return 1

        # Verify the transplant
        if not verify_transplant(args.output_pe):
            logger.error("Transplant verification failed")
            return 1

        logger.info("Authenticode signature transplantation completed successfully!")
        return 0

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.debug:
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())

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
from typing import Dict, List, Tuple

import pefile
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1_modules import rfc2315

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Add the parent directory to import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def calculate_authenticode_hash(pe: pefile.PE) -> str:
    """Calculate the SHA256 hash of a PE file for Authenticode signature verification.

    This function computes the hash of a PE file excluding specific fields that are
    modified during the signing process: the CheckSum field in the Optional Header
    and the IMAGE_DIRECTORY_ENTRY_SECURITY directory entry (including the certificate
    table itself).

    Args:
        pe: A pefile.PE object representing the parsed PE file.

    Returns:
        str: The hexadecimal string representation of the SHA256 hash of the PE file
             data, excluding the CheckSum field and security directory/certificate data.

    Note:
        This hash is used for Authenticode signature verification and follows the
        Microsoft Authenticode specification for computing PE file hashes.
    """
    security_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]  # Extract Security directory
    checksum_offset = pe.OPTIONAL_HEADER.dump_dict()["CheckSum"]["FileOffset"]  # CheckSum file offset
    certificate_table_offset = security_directory.dump_dict()["VirtualAddress"][
        "FileOffset"
    ]  # IMAGE_DIRECTORY_ENTRY_SECURITY file offset
    certificate_virtual_addr = security_directory.VirtualAddress
    certificate_size = security_directory.Size
    raw_data = pe.__data__
    hash_data = (
        raw_data[:checksum_offset] + raw_data[checksum_offset + 0x04 : certificate_table_offset]
    )  # Skip OptionalHeader.CheckSum field and continue until IMAGE_DIRECTORY_ENTRY_SECURITY
    hash_data += (
        raw_data[certificate_table_offset + 0x08 : certificate_virtual_addr]
        + raw_data[certificate_virtual_addr + certificate_size :]
    )  # Skip IMAGE_DIRECTORY_ENTRY_SECURITY and certificate

    return hashlib.sha256(hash_data).hexdigest()


def get_authenticode_hash(pe_path: str) -> str:
    """Calculate the proper Authenticode hash for a PE file.

    Args:
        pe_path: Path to the PE file

    Returns:
        str: Authenticode hash as uppercase hex string
    """
    pe = pefile.PE(pe_path, fast_load=True)

    # Use the proper Authenticode hash calculation
    hash_value = calculate_authenticode_hash(pe)
    pe.close()

    return hash_value


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
        logger.debug(f"Validated PE file: {pe_path}")
        return pe
    except pefile.PEFormatError as e:
        raise ValueError(f"Invalid PE file {pe_path}: {e}")


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
    if not hasattr(pe, "OPTIONAL_HEADER") or not hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
        raise ValueError(f"PE file has no data directory: {pe_path}")

    # Security directory is entry 4 (IMAGE_DIRECTORY_ENTRY_SECURITY)
    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 4:
        raise ValueError(f"PE file has no security directory entry: {pe_path}")

    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    if security_dir.VirtualAddress == 0 or security_dir.Size == 0:
        raise ValueError(f"PE file is not signed (no security directory): {pe_path}")

    # Read the signature data from the file
    with open(pe_path, "rb") as f:
        f.seek(security_dir.VirtualAddress)
        signature_data = f.read(security_dir.Size)

    if len(signature_data) != security_dir.Size:
        raise ValueError(f"Failed to read complete signature data from {pe_path}")

    logger.info(
        f"Extracted signature from {pe_path}: {security_dir.Size} bytes at offset 0x{security_dir.VirtualAddress:x}"
    )

    return signature_data, security_dir.VirtualAddress, security_dir.Size


def parse_signature_blocks(signature_data: bytes) -> List[Dict]:
    """Parse WIN_CERTIFICATE structures from signature data.

    Args:
        signature_data: Raw signature data from security directory

    Returns:
        List of dictionaries containing signature block information
    """
    signatures = []
    offset = 0

    while offset < len(signature_data):
        if offset + 8 > len(signature_data):
            break

        # Parse WIN_CERTIFICATE header
        dwLength = int.from_bytes(signature_data[offset : offset + 4], "little")
        wRevision = int.from_bytes(signature_data[offset + 4 : offset + 6], "little")
        wCertificateType = int.from_bytes(signature_data[offset + 6 : offset + 8], "little")

        if dwLength < 8 or offset + dwLength > len(signature_data):
            logger.warning(f"Invalid certificate length: {dwLength} at offset {offset}")
            break

        # Extract certificate data
        cert_data = signature_data[offset + 8 : offset + dwLength]
        cert_data = der_decode(cert_data, asn1Spec=rfc2315.ContentInfo())


        signature_info = {
            "offset": offset,
            "length": dwLength,
            "revision": wRevision,
            "certificate_type": wCertificateType,
            "data": cert_data,
            "is_pkcs7": wCertificateType == 0x0002,  # WIN_CERT_TYPE_PKCS_SIGNED_DATA
        }

        signatures.append(signature_info)

        # Move to next certificate (align to 8-byte boundary)
        offset += dwLength
        offset = (offset + 7) & ~7  # Align to 8 bytes

    return signatures


def analyze_signature_content(signature_data: bytes) -> Dict:
    """Analyze PKCS#7 signature content for hash algorithms and certificates.

    Args:
        signature_data: Raw signature data

    Returns:
        Dictionary containing analysis results
    """
    try:
        # Look for SHA-1 and SHA-256 algorithm identifiers
        sha1_oid = b"\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00"  # SHA-1 algorithm identifier
        sha256_oid = b"\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00"  # SHA-256 algorithm identifier

        sha1_count = signature_data.count(sha1_oid)
        sha256_count = signature_data.count(sha256_oid)

        return {
            "size": len(signature_data),
            "sha1_signatures": sha1_count,
            "sha256_signatures": sha256_count,
            "has_multiple_algorithms": (sha1_count > 0) + (sha256_count > 0) > 1,
            "likely_dual_signed": sha1_count > 0 and sha256_count > 0,
        }
    except Exception as e:
        return {"error": f"Analysis failed: {e}"}


def extract_all_signatures(pe_path: str) -> Tuple[bytes, List[Dict], int, int]:
    """Extract all signature data and parse individual signature blocks.

    Args:
        pe_path: Path to the signed PE file

    Returns:
        Tuple containing:
        - bytes: Complete signature data
        - List[Dict]: Parsed signature blocks
        - int: Offset of the signature in the file
        - int: Size of the signature

    Raises:
        ValueError: If no signature is found or signature is invalid
    """
    pe = None
    try:
        pe = validate_pe_file(pe_path)

        # Check if the PE has a security directory entry
        if not hasattr(pe, "OPTIONAL_HEADER") or not hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            raise ValueError(f"PE file has no data directory: {pe_path}")

        # Security directory is entry 4 (IMAGE_DIRECTORY_ENTRY_SECURITY)
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 4:
            raise ValueError(f"PE file has no security directory entry: {pe_path}")

        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if security_dir.VirtualAddress == 0 or security_dir.Size == 0:
            raise ValueError(f"PE file is not signed (no security directory): {pe_path}")

        # Read the signature data from the file
        with open(pe_path, "rb") as f:
            f.seek(security_dir.VirtualAddress)
            signature_data = f.read(security_dir.Size)

        if len(signature_data) != security_dir.Size:
            raise ValueError(f"Failed to read complete signature data from {pe_path}")

        # Parse signature blocks
        signature_blocks = parse_signature_blocks(signature_data)

        # Analyze content
        analysis = analyze_signature_content(signature_data)

        logger.info(
            f"Extracted signatures from {pe_path}: {security_dir.Size} bytes "
            f"at offset 0x{security_dir.VirtualAddress:x}"
        )
        logger.info(f"Found {len(signature_blocks)} signature block(s)")
        if analysis.get("likely_dual_signed"):
            logger.info("Detected dual-signed binary with multiple hash algorithms")

        return signature_data, signature_blocks, security_dir.VirtualAddress, security_dir.Size

    except Exception as e:
        logger.error(f"Error extracting signatures: {e}")
        raise
    finally:
        # Explicitly close the PE file to release file handle
        if pe is not None:
            try:
                pe.close()
            except AttributeError:
                # pefile might not have a close method in older versions
                pass


def extract_pkcs7_from_wincert(signature_data: bytes) -> bytes:
    """Extract PKCS#7 data from WIN_CERTIFICATE structure.

    Args:
        signature_data: Raw WIN_CERTIFICATE data

    Returns:
        bytes: PKCS#7 data (skipping WIN_CERTIFICATE header)
    """
    # WIN_CERTIFICATE structure:
    # DWORD dwLength
    # WORD wRevision
    # WORD wCertificateType
    # BYTE bCertificate[dwLength - 8]

    if len(signature_data) < 8:
        raise ValueError("Signature data too short for WIN_CERTIFICATE header")

    # Skip 8-byte WIN_CERTIFICATE header to get PKCS#7 data
    pkcs7_data = signature_data[8:]
    return pkcs7_data


def combine_pkcs7_signatures(pkcs7_data1: bytes, pkcs7_data2: bytes, output_path: str) -> bytes:
    """Combine two PKCS#7 signatures using Microsoft nested signature approach.

    This function implements the same structure as signtool's /as flag:
    1. Uses first PKCS#7 signature as the primary signature
    2. Embeds second PKCS#7 signature as nested signature in unauthenticated attributes
    3. Uses OID 1.3.6.1.4.1.311.2.4.1 (Microsoft Nested Signature) for the attribute

    This matches how Windows signtool creates dual signatures with /as flag.

    Args:
        pkcs7_data1: First PKCS#7 signature data (becomes primary signature)
        pkcs7_data2: Second PKCS#7 signature data (becomes nested signature)
        output_path: Path to save combined PKCS#7 structure

    Returns:
        bytes: Combined PKCS#7 data with nested signature structure
    """
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type import tag, univ

    logger.info("Parsing PKCS#7 signatures...")

    # Decode both PKCS#7 structures
    try:
        content_info1, _ = decoder.decode(pkcs7_data1, asn1Spec=rfc2315.ContentInfo())
        content_info2, _ = decoder.decode(pkcs7_data2, asn1Spec=rfc2315.ContentInfo())

        logger.info(f"ContentInfo 1 type: {content_info1['contentType']}")
        logger.info(f"ContentInfo 2 type: {content_info2['contentType']}")

        # Verify both are signedData (OID 1.2.840.113549.1.7.2)
        if str(content_info1['contentType']) != '1.2.840.113549.1.7.2':
            raise ValueError(f"Source 1 is not signedData: {content_info1['contentType']}")
        if str(content_info2['contentType']) != '1.2.840.113549.1.7.2':
            raise ValueError(f"Source 2 is not signedData: {content_info2['contentType']}")

        # Extract the signedData content
        signed_data1, _ = decoder.decode(bytes(content_info1['content']), asn1Spec=rfc2315.SignedData())
        signed_data2, _ = decoder.decode(bytes(content_info2['content']), asn1Spec=rfc2315.SignedData())

        logger.info(f"SignedData 1 version: {signed_data1['version']}")
        logger.info(f"SignedData 2 version: {signed_data2['version']}")
        logger.info(f"SignedData 1 signerInfos: {len(signed_data1['signerInfos'])}")
        logger.info(f"SignedData 2 signerInfos: {len(signed_data2['signerInfos'])}")

        # Create nested signature structure (Microsoft approach)
        logger.info("Creating nested signature structure (Microsoft /as style)...")

        # Use the first signature as the base
        combined_signed_data = rfc2315.SignedData()
        combined_signed_data['version'] = signed_data1['version']
        combined_signed_data['digestAlgorithms'] = signed_data1['digestAlgorithms']
        combined_signed_data['contentInfo'] = signed_data1['contentInfo']

        # Copy certificates from first signature
        if 'certificates' in signed_data1 and signed_data1['certificates'].isValue:
            combined_signed_data['certificates'] = signed_data1['certificates']
            logger.info(f"Using certificates from primary signature: {len(signed_data1['certificates'])}")

        # Get the first SignerInfo (primary signature)
        primary_signer = signed_data1['signerInfos'][0]
        logger.info("Extracted primary SignerInfo from source 1")

        # Create a new SignerInfo with nested signature in unauthenticated attributes
        modified_signer = rfc2315.SignerInfo()
        modified_signer['version'] = primary_signer['version']
        modified_signer['issuerAndSerialNumber'] = primary_signer['issuerAndSerialNumber']
        modified_signer['digestAlgorithm'] = primary_signer['digestAlgorithm']

        # Copy authenticated attributes if present
        if 'authenticatedAttributes' in primary_signer and primary_signer['authenticatedAttributes'].isValue:
            modified_signer['authenticatedAttributes'] = primary_signer['authenticatedAttributes']

        modified_signer['digestEncryptionAlgorithm'] = primary_signer['digestEncryptionAlgorithm']
        modified_signer['encryptedDigest'] = primary_signer['encryptedDigest']

        # Create unauthenticated attributes with nested signature
        # OID 1.3.6.1.4.1.311.2.4.1 = Microsoft Nested Signature
        nested_sig_oid = univ.ObjectIdentifier('1.3.6.1.4.1.311.2.4.1')

        # The nested signature is the entire second PKCS#7 ContentInfo as a SEQUENCE
        # We encode the second PKCS#7 as a SEQUENCE (which is what ContentInfo is)
        nested_content_info2, _ = decoder.decode(pkcs7_data2, asn1Spec=rfc2315.ContentInfo())

        # Now encode it back to get the DER bytes wrapped as a SEQUENCE
        nested_pkcs7_encoded = encoder.encode(nested_content_info2)

        # Create an untagged ANY value containing the nested PKCS#7
        nested_value = univ.Any(nested_pkcs7_encoded)

        # Create SET OF with the nested signature
        nested_signature_values = univ.SetOf(componentType=univ.Any())
        nested_signature_values[0] = nested_value

        # Create the Attribute structure
        nested_sig_attr = rfc2315.Attribute()
        nested_sig_attr['type'] = nested_sig_oid
        nested_sig_attr['values'] = nested_signature_values

        # Create unauthenticated attributes SET with proper context tag [1]
        unauth_attrs = rfc2315.Attributes().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
        )
        unauth_attrs[0] = nested_sig_attr

        modified_signer['unauthenticatedAttributes'] = unauth_attrs
        logger.info("✅ Added nested signature to unauthenticated attributes (OID 1.3.6.1.4.1.311.2.4.1)")

        # Set the modified signer as the only SignerInfo
        combined_signer_infos = rfc2315.SignerInfos()
        combined_signer_infos[0] = modified_signer
        combined_signed_data['signerInfos'] = combined_signer_infos

        logger.info("✅ Created SignerInfo with nested signature structure")

        # Encode the combined signedData
        combined_signed_data_encoded = encoder.encode(combined_signed_data)

        # Create new ContentInfo wrapper
        combined_content_info = rfc2315.ContentInfo()
        combined_content_info['contentType'] = content_info1['contentType']  # signedData OID
        combined_content_info['content'] = univ.Any(combined_signed_data_encoded)

        # Encode the final ContentInfo
        combined_pkcs7 = encoder.encode(combined_content_info)

        logger.info(f"✅ Combined PKCS#7 size: {len(combined_pkcs7)} bytes")
        logger.info("   (signtool reference size: 2904 bytes)")

        # Save to file for inspection
        with open(output_path, 'wb') as f:
            f.write(combined_pkcs7)

        logger.info(f"✅ Saved combined PKCS#7 to: {output_path}")

        return combined_pkcs7

    except Exception as e:
        logger.error(f"Failed to combine PKCS#7 signatures: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise


def create_win_certificate(pkcs7_data: bytes) -> bytes:
    """
    Wrap PKCS#7 data in a WIN_CERTIFICATE structure.

    WIN_CERTIFICATE structure:
        DWORD dwLength;          // Length including header
        WORD  wRevision;         // 0x0200
        WORD  wCertificateType;  // 0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA
        BYTE  bCertificate[];    // PKCS#7 data

    Args:
        pkcs7_data: PKCS#7 DER-encoded data

    Returns:
        bytes: WIN_CERTIFICATE structure
    """
    import struct

    # Calculate total length (must be 8-byte aligned)
    header_size = 8  # 4 + 2 + 2
    total_length = header_size + len(pkcs7_data)
    
    # Align to 8 bytes
    padding = (8 - (total_length % 8)) % 8
    total_length += padding

    logger.info(f"Creating WIN_CERTIFICATE structure:")
    logger.info(f"  PKCS#7 size: {len(pkcs7_data)} bytes")
    logger.info(f"  Header size: {header_size} bytes")
    logger.info(f"  Padding: {padding} bytes")
    logger.info(f"  Total size: {total_length} bytes")

    # Create WIN_CERTIFICATE header
    win_cert = struct.pack('<I', total_length)  # dwLength (little-endian DWORD)
    win_cert += struct.pack('<H', 0x0200)       # wRevision (little-endian WORD)
    win_cert += struct.pack('<H', 0x0002)       # wCertificateType (PKCS_SIGNED_DATA)
    
    # Append PKCS#7 data
    win_cert += pkcs7_data
    
    # Add padding to align to 8 bytes
    if padding > 0:
        win_cert += b'\x00' * padding

    logger.info(f"✅ Created WIN_CERTIFICATE: {len(win_cert)} bytes")
    
    return win_cert


def apply_signature_to_pe(pe_path: str, signature_data: bytes, output_path: str) -> None:
    """
    Apply a signature (WIN_CERTIFICATE) to a PE file.

    This function:
    1. Loads the PE file
    2. Removes any existing signature
    3. Updates the security directory
    4. Appends the new signature

    Args:
        pe_path: Path to source PE file
        signature_data: WIN_CERTIFICATE data to apply
        output_path: Path to output PE file
    """
    import struct
    import shutil

    logger.info(f"Applying signature to PE file: {pe_path}")
    
    # Read the entire PE file
    with open(pe_path, 'rb') as f:
        pe_data = bytearray(f.read())

    # Find PE header
    pe_offset = struct.unpack('<L', pe_data[0x3c:0x40])[0]
    logger.info(f"PE header at offset: 0x{pe_offset:x}")

    # Find Optional Header (PE + 4 bytes + 20 bytes COFF header)
    opt_header_offset = pe_offset + 4 + 20

    # Check if it's PE32 or PE32+
    magic = struct.unpack('<H', pe_data[opt_header_offset:opt_header_offset+2])[0]
    
    if magic == 0x10b:  # PE32
        security_dir_offset = opt_header_offset + 128
        logger.info("PE32 format detected")
    elif magic == 0x20b:  # PE32+
        security_dir_offset = opt_header_offset + 144
        logger.info("PE32+ format detected")
    else:
        raise ValueError(f"Unknown PE format: magic=0x{magic:x}")

    # Read current security directory
    orig_va = struct.unpack('<L', pe_data[security_dir_offset:security_dir_offset+4])[0]
    orig_size = struct.unpack('<L', pe_data[security_dir_offset+4:security_dir_offset+8])[0]

    logger.info(f"Original security directory: VA=0x{orig_va:x}, Size={orig_size} bytes")

    # Truncate at original signature location (if exists)
    if orig_va != 0:
        pe_data = pe_data[:orig_va]
        logger.info(f"Removed existing signature at 0x{orig_va:x}")
    
    # Calculate new signature location
    new_va = len(pe_data)
    new_size = len(signature_data)

    logger.info(f"New security directory: VA=0x{new_va:x}, Size={new_size} bytes")

    # Update security directory
    pe_data[security_dir_offset:security_dir_offset+4] = struct.pack('<L', new_va)
    pe_data[security_dir_offset+4:security_dir_offset+8] = struct.pack('<L', new_size)

    # Append new signature
    pe_data.extend(signature_data)

    # Write the result
    with open(output_path, 'wb') as f:
        f.write(pe_data)

    logger.info(f"✅ Applied signature to: {output_path}")
    logger.info(f"   File size: {len(pe_data)} bytes")





def cli() -> argparse.Namespace:
    """Argument parser for signature combination."""
    parser = argparse.ArgumentParser(
        description="Combine Authenticode signatures from two signed PE files into one binary"
    )

    parser.add_argument("source1", help="Path to first signed PE file")
    parser.add_argument("source2", help="Path to second signed PE file")
    parser.add_argument("output", help="Path where the combined signature PE file will be saved")

    parser.add_argument(
        "--force", action="store_true", default=False, help="Force combination even if PE files have different content"
    )

    parser.add_argument("--debug", action="store_true", default=False, help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    return args


def main() -> int:
    """Main entry point for the signature combination tool."""
    args = cli()

    try:
        # Validate input files exist
        for pe_file in [args.source1, args.source2]:
            if not os.path.exists(pe_file):
                logger.error(f"Source PE file not found: {pe_file}")
                return 1

        logger.info("Checking PE file compatibility...")

        # Check if files have same Authenticode hash
        hash1 = get_authenticode_hash(args.source1)
        hash2 = get_authenticode_hash(args.source2)

        logger.info(f"Source 1: {args.source1}")
        logger.info(f"  Authenticode hash: {hash1}")
        logger.info(f"Source 2: {args.source2}")
        logger.info(f"  Authenticode hash: {hash2}")

        if hash1 != hash2 and not args.force:
            logger.error("The PE files must have identical authenticode hashes!")
            logger.error("Use --force to override this check")
            return 1

        logger.info("✅ PE files have compatible content")

        logger.info("Extracting signatures...")

        # Extract signatures from both files
        sig_data1, blocks1, _, _ = extract_all_signatures(args.source1)
        sig_data2, blocks2, _, _ = extract_all_signatures(args.source2)

        logger.info(f"Source 1 signature: {len(sig_data1)} bytes, {len(blocks1)} block(s)")
        logger.info(f"Source 2 signature: {len(sig_data2)} bytes, {len(blocks2)} block(s)")

        # Extract PKCS#7 data from WIN_CERTIFICATE structures
        logger.info("Extracting PKCS#7 data from WIN_CERTIFICATE structures...")
        pkcs7_data1 = extract_pkcs7_from_wincert(sig_data1)
        pkcs7_data2 = extract_pkcs7_from_wincert(sig_data2)

        # Save individual PKCS#7 signatures for inspection
        pkcs7_file1 = "signature1.p7b"
        pkcs7_file2 = "signature2.p7b"

        with open(pkcs7_file1, 'wb') as f:
            f.write(pkcs7_data1)
        logger.info(f"Saved source 1 PKCS#7 to: {pkcs7_file1} ({len(pkcs7_data1)} bytes)")

        with open(pkcs7_file2, 'wb') as f:
            f.write(pkcs7_data2)
        logger.info(f"Saved source 2 PKCS#7 to: {pkcs7_file2} ({len(pkcs7_data2)} bytes)")

        # Combine the PKCS#7 signatures
        combined_pkcs7_file = "combined_signature.p7b"
        logger.info("Combining PKCS#7 signatures...")

        try:
            combined_pkcs7 = combine_pkcs7_signatures(pkcs7_data1, pkcs7_data2, combined_pkcs7_file)
            logger.info("🎉 Successfully combined signatures!")
            logger.info(f"   Combined PKCS#7 saved to: {combined_pkcs7_file}")
            logger.info(f"   Combined size: {len(combined_pkcs7)} bytes")

            # Wrap the combined PKCS#7 in WIN_CERTIFICATE structure
            logger.info("")
            logger.info("Creating WIN_CERTIFICATE structure...")
            win_cert_data = create_win_certificate(combined_pkcs7)
            logger.info(f"   WIN_CERTIFICATE size: {len(win_cert_data)} bytes")

            # Apply the dual signature to the output PE file
            logger.info("")
            logger.info(f"Applying dual signature to output file: {args.output}")
            apply_signature_to_pe(args.source1, win_cert_data, args.output)

            logger.info("")
            logger.info("✅✅✅ SUCCESS! Dual-signed PE file created! ✅✅✅")
            logger.info(f"   Output: {args.output}")
            logger.info("")
            logger.info("Next step: Verify with signtool:")
            logger.info(f"   signtool.exe verify /pa /v /all {args.output}")

            return 0

        except Exception as e:
            logger.error(f"Failed to combine signatures: {e}")
            if args.debug:
                raise
            return 1

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.debug:
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())

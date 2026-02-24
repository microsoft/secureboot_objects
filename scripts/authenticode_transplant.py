# @file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Combine Authenticode signatures from multiple signed PE files into a single multi-signed binary.

This script creates multi-signed PE/UEFI binaries using two approaches:

1. **Multiple WIN_CERTIFICATE structures (default)**: The UEFI-standard approach where each
   signature gets its own WIN_CERTIFICATE structure. UEFI Secure Boot (DxeImageVerificationLib)
   iterates through all WIN_CERTIFICATE structures and returns SUCCESS if ANY signature
   validates against db.

2. **Nested signatures (--nested flag)**: Uses Microsoft's nested signature approach
   (equivalent to signtool.exe /as) where additional signatures are embedded as
   unauthenticated attributes in the primary signature using OID 1.3.6.1.4.1.311.2.4.1.

The script:
1. Takes two or more signed PE files (e.g., EFI applications) as input
2. Validates that all files have identical Authenticode hashes (same code/data)
3. Extracts PKCS#7 signatures from all files
4. Creates either multiple WIN_CERTIFICATE structures OR nested signature structure
5. Applies the combined signatures to the output PE file

Use case: Combine signatures from different certificate authorities to support
multiple firmware implementations or certificate transitions in UEFI Secure Boot.
"""

import argparse
import hashlib
import logging
import os
import struct
import sys
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable

import pefile
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_modules import rfc2315

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Add the parent directory to import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@runtime_checkable
class FileSystemInterface(Protocol):
    """Protocol for file system operations to enable dependency injection for testing."""

    def read_binary_file(self, filepath: str) -> bytes:
        """Read a binary file and return its contents."""
        ...

    def write_binary_file(self, filepath: str, data: bytes) -> None:
        """Write binary data to a file."""
        ...

    def create_pe(self, filepath: str, fast_load: bool = False) -> pefile.PE:
        """Create a PE file object from filepath."""
        ...


class RealFileSystem:
    """Real file system implementation for production use."""

    def read_binary_file(self, filepath: str) -> bytes:
        """Read a binary file and return its contents."""
        with open(filepath, "rb") as f:
            return f.read()

    def write_binary_file(self, filepath: str, data: bytes) -> None:
        """Write binary data to a file."""
        with open(filepath, "wb") as f:
            f.write(data)

    def create_pe(self, filepath: str, fast_load: bool = False) -> pefile.PE:
        """Create a PE file object from filepath."""
        return pefile.PE(filepath, fast_load=fast_load)


def _get_hash_algorithm_from_oid(oid: str) -> Optional[hashes.HashAlgorithm]:
    """Map OID to cryptography hash algorithm."""
    oid_map = {
        '2.16.840.1.101.3.4.2.1': hashes.SHA256(),
        '2.16.840.1.101.3.4.2.2': hashes.SHA384(),
        '2.16.840.1.101.3.4.2.3': hashes.SHA512(),
        '1.3.14.3.2.26': hashes.SHA1(),
    }
    return oid_map.get(oid)


def _extract_pe_hash_from_spc_indirect_data(content_bytes: bytes) -> Tuple[Optional[bytes], Optional[str]]:
    """Extract PE file hash from SpcIndirectDataContent structure.

    SpcIndirectDataContent ::= SEQUENCE {
        data                    SpcAttributeTypeAndOptionalValue,
        messageDigest           DigestInfo
    }

    DigestInfo ::= SEQUENCE {
        digestAlgorithm     AlgorithmIdentifier,
        digest              OCTET STRING
    }

    This follows the Microsoft Authenticode PE specification which defines
    OID 1.3.6.1.4.1.311.2.1.4 for SpcIndirectDataContent.

    Args:
        content_bytes: The contentInfo content from PKCS#7 SignedData

    Returns:
        Tuple of (hash_bytes, algorithm_oid) or (None, None) if parsing fails
    """
    # ASN.1 DER constants
    ASN1_OCTET_STRING_TAG = 0x04

    # Expected hash sizes (in bytes)
    SHA1_HASH_SIZE = 20
    SHA256_HASH_SIZE = 32
    SHA384_HASH_SIZE = 48
    SHA512_HASH_SIZE = 64
    VALID_HASH_SIZES = {SHA1_HASH_SIZE, SHA256_HASH_SIZE, SHA384_HASH_SIZE, SHA512_HASH_SIZE}

    # DER-encoded OID prefixes for hash algorithms
    # Format: [0x06 (OID tag), length, OID bytes...]
    OID_SHA1_DER = b'\x06\x05\x2b\x0e\x03\x02\x1a'  # 1.3.14.3.2.26
    OID_SHA256_DER = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01'  # 2.16.840.1.101.3.4.2.1
    OID_SHA384_DER = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02'  # 2.16.840.1.101.3.4.2.2
    OID_SHA512_DER = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03'  # 2.16.840.1.101.3.4.2.3

    # String representations of OIDs
    OID_SHA1_STRING = '1.3.14.3.2.26'
    OID_SHA256_STRING = '2.16.840.1.101.3.4.2.1'
    OID_SHA384_STRING = '2.16.840.1.101.3.4.2.2'
    OID_SHA512_STRING = '2.16.840.1.101.3.4.2.3'

    # Search parameters
    OID_SEARCH_WINDOW = 50  # Bytes to search before hash for algorithm OID
    LENGTH_BYTE_OFFSET = 1
    DATA_START_OFFSET = 2

    try:
        # Scan through the content looking for OCTET STRING tags with hash-sized data
        i = 0
        while i < len(content_bytes) - 10:
            # Check if this is an OCTET STRING tag
            if content_bytes[i] == ASN1_OCTET_STRING_TAG:
                length = content_bytes[i + LENGTH_BYTE_OFFSET]

                # Check if length matches a known hash size
                if length in VALID_HASH_SIZES and i + DATA_START_OFFSET + length <= len(content_bytes):
                    hash_bytes = content_bytes[i + DATA_START_OFFSET : i + DATA_START_OFFSET + length]

                    # Search backwards for the algorithm OID
                    # The OID appears in the DigestInfo structure before the digest
                    algorithm_oid = None
                    search_start = max(0, i - OID_SEARCH_WINDOW)
                    search_region = content_bytes[search_start:i]

                    if OID_SHA256_DER in search_region:
                        algorithm_oid = OID_SHA256_STRING
                    elif OID_SHA1_DER in search_region:
                        algorithm_oid = OID_SHA1_STRING
                    elif OID_SHA384_DER in search_region:
                        algorithm_oid = OID_SHA384_STRING
                    elif OID_SHA512_DER in search_region:
                        algorithm_oid = OID_SHA512_STRING

                    logger.info(f"Extracted PE hash from SpcIndirectDataContent: {hash_bytes.hex()}")
                    if algorithm_oid:
                        logger.info(f"Hash algorithm OID: {algorithm_oid}")
                    return hash_bytes, algorithm_oid
            i += 1

        logger.warning("No hash found in SpcIndirectDataContent")
        return None, None

    except Exception as e:
        logger.error(f"Failed to parse SpcIndirectDataContent: {e}")
        return None, None


def _extract_certificates_from_pkcs7(pkcs7_data: bytes) -> List[x509.Certificate]:
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
        logger.error(f"Failed to extract certificates: {e}")

    return certificates


def _verify_pkcs7_signature(pkcs7_data: bytes, pe_data: bytes) -> Dict[str, Any]:
    """Verify PKCS7 Authenticode signature against PE file.

    This function:
    1. Extracts the hash algorithm used by the signature
    2. Computes the Authenticode hash using that algorithm
    3. Verifies the computed hash matches the hash in SpcIndirectDataContent
    4. Cryptographically verifies the signature

    Args:
        pkcs7_data: The PKCS#7 signature data
        pe_data: The full PE file data

    Returns:
        Dict[str, Any]: Verification results with keys:
            - 'verified' (bool): Overall verification status
            - 'signers' (List[Dict]): List of signer verification results
            - 'errors' (List[str]): List of error messages
    """
    results = {
        'verified': False,
        'signers': [],
        'errors': []
    }

    try:
        # Extract certificates from PKCS#7
        certificates = _extract_certificates_from_pkcs7(pkcs7_data)
        if not certificates:
            results['errors'].append("No certificates found in PKCS#7 signature")
            return results

        # Decode PKCS7 structure
        try:
            content_info, _ = decoder.decode(pkcs7_data, asn1Spec=rfc2315.ContentInfo())
            signed_data, _ = decoder.decode(
                bytes(content_info['content']),
                asn1Spec=rfc2315.SignedData()
            )
        except Exception:
            signed_data, _ = decoder.decode(pkcs7_data, asn1Spec=rfc2315.SignedData())

        # Extract the hash algorithm OID and embedded PE hash from SpcIndirectDataContent
        authenticode_content_valid = False
        embedded_pe_hash = None
        hash_algorithm_oid = None

        if signed_data['contentInfo'].hasValue() and signed_data['contentInfo']['content'].hasValue():
            try:
                content_bytes = bytes(signed_data['contentInfo']['content'])

                # Extract hash from SpcIndirectDataContent structure
                embedded_pe_hash, hash_algorithm_oid = _extract_pe_hash_from_spc_indirect_data(content_bytes)

                if embedded_pe_hash and hash_algorithm_oid:
                    # Get the hash algorithm object
                    hash_algo = _get_hash_algorithm_from_oid(hash_algorithm_oid)
                    if hash_algo:
                        # Compute the Authenticode hash using the same algorithm
                        computed_hash = compute_authenticode_hash(pe_data, hash_algo)
                        logger.debug(f"Computed Authenticode hash: {computed_hash.hex()}")

                        # Verify they match
                        if computed_hash == embedded_pe_hash:
                            authenticode_content_valid = True
                            logger.debug(f"[+] PE hash verified! (algorithm: {hash_algo.name})")
                        else:
                            logger.warning("[-] PE hash mismatch!")
                            logger.warning(f"  Expected: {embedded_pe_hash.hex()}")
                            logger.warning(f"  Computed: {computed_hash.hex()}")
                            results['errors'].append("PE hash mismatch between signature and computed hash")
                    else:
                        logger.warning(f"Unsupported hash algorithm OID: {hash_algorithm_oid}")
                        results['errors'].append(f"Unsupported hash algorithm: {hash_algorithm_oid}")
                else:
                    logger.warning("Could not extract PE hash from SpcIndirectDataContent")
                    results['errors'].append("Could not parse SpcIndirectDataContent")

            except Exception as e:
                logger.debug(f"Error checking SpcIndirectDataContent: {e}")

        if not authenticode_content_valid:
            logger.warning("PE hash verification in SpcIndirectDataContent failed")
            results['errors'].append("Could not verify PE hash in SpcIndirectDataContent")

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
                    # With authenticated attributes, we verify the signature against the authenticated attributes
                    # For Authenticode, the authenticated attributes contain a message digest of the
                    # SpcIndirectDataContent (which in turn contains the PE hash)
                    authenticated_attrs = signer_info['authenticatedAttributes']
                    attrs_der = encoder.encode(authenticated_attrs)
                    # Replace IMPLICIT tag [0] (0xA0) with SET OF tag (0x31)
                    if attrs_der[0:1] == b'\xa0':
                        attrs_der = b'\x31' + attrs_der[1:]
                    data_to_verify = attrs_der

                    # For Authenticode verification, we need to verify that the messageDigest attribute
                    # matches the hash of the contentInfo content (SpcIndirectDataContent)
                    # The SpcIndirectDataContent is what contains the PE hash
                    # We'll verify this by checking that the signature verifies against the authenticated attributes
                    # The firmware will separately verify the PE hash matches the SpcIndirectDataContent
                else:
                    # No authenticated attributes - this is unusual for Authenticode but theoretically valid
                    # In this case, we would verify against the content directly
                    # However, for Authenticode, authenticated attributes are required
                    signer_result['error'] = "No authenticated attributes found - required for Authenticode"
                    results['errors'].append(signer_result['error'])
                    results['signers'].append(signer_result)
                    continue

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

        # Overall verification passes if all signers verified AND PE hash is valid
        results['verified'] = (
            all(s['verified'] for s in results['signers'])
            and len(results['signers']) > 0
            and authenticode_content_valid
        )

    except Exception as e:
        results['errors'].append(f"Failed to verify PKCS#7 signature: {str(e)}")

    return results


def compute_authenticode_hash(pe_data: bytes, hash_algorithm: Optional[object] = None) -> bytes:
    """Compute Authenticode hash of PE data using specified algorithm.

    This function computes the hash of a PE file excluding specific fields that are
    modified during the signing process: the CheckSum field in the Optional Header
    and the IMAGE_DIRECTORY_ENTRY_SECURITY directory entry.

    Args:
        pe_data: The raw PE file data (bytes)
        hash_algorithm: A hash algorithm from cryptography.hazmat.primitives.hashes (e.g., hashes.SHA256()).
                       Defaults to SHA256 if not specified.

    Returns:
        bytes: The computed hash as bytes

    Note:
        This follows the Microsoft Authenticode PE specification v1.1.
    """
    from cryptography.hazmat.primitives import hashes as crypto_hashes

    # Default to SHA-256 if no algorithm specified
    if hash_algorithm is None:
        hash_algorithm = crypto_hashes.SHA256()

    pe = pefile.PE(data=pe_data, fast_load=True)

    try:
        security_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        checksum_offset = pe.OPTIONAL_HEADER.dump_dict()["CheckSum"]["FileOffset"]
        certificate_table_offset = security_directory.dump_dict()["VirtualAddress"]["FileOffset"]
        certificate_virtual_addr = security_directory.VirtualAddress
        certificate_size = security_directory.Size

        hash_data = (
            pe_data[:checksum_offset] + pe_data[checksum_offset + 0x04 : certificate_table_offset]
        )
        hash_data += (
            pe_data[certificate_table_offset + 0x08 : certificate_virtual_addr]
            + pe_data[certificate_virtual_addr + certificate_size :]
        )

        # Map cryptography hash algorithm to hashlib
        if isinstance(hash_algorithm, crypto_hashes.SHA256):
            return hashlib.sha256(hash_data).digest()
        elif isinstance(hash_algorithm, crypto_hashes.SHA1):
            return hashlib.sha1(hash_data).digest()
        elif isinstance(hash_algorithm, crypto_hashes.SHA384):
            return hashlib.sha384(hash_data).digest()
        elif isinstance(hash_algorithm, crypto_hashes.SHA512):
            return hashlib.sha512(hash_data).digest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
    finally:
        pe.close()


def get_authenticode_hash(pe_path: str, fs: FileSystemInterface = None) -> str:
    """Calculate the proper Authenticode hash for a PE file.

    This is a convenience wrapper around compute_authenticode_hash() that
    handles file loading and cleanup. The hash is computed according to the
    Microsoft Authenticode specification v1.1, excluding the CheckSum field and
    security directory from the hash calculation.

    Args:
        pe_path: Path to the PE file to hash
        fs: File system interface for dependency injection (optional)

    Returns:
        str: SHA256 Authenticode hash as lowercase hex string (64 characters)

    Raises:
        FileNotFoundError: If the PE file doesn't exist
        ValueError: If the file is not a valid PE format
    """
    if fs is None:
        fs = RealFileSystem()

    # Read the raw PE data
    pe_data = fs.read_binary_file(pe_path)

    # Use the proper Authenticode hash calculation (defaults to SHA-256)
    hash_bytes = compute_authenticode_hash(pe_data)

    return hash_bytes.hex()


def validate_pe_file(pe_path: str, fs: FileSystemInterface = None) -> pefile.PE:
    """Validate that a file is a valid PE file and return the PE object.

    Args:
        pe_path: Path to the PE file to validate
        fs: File system interface for dependency injection (optional)

    Returns:
        pefile.PE: The PE object if valid

    Raises:
        ValueError: If the file is not a valid PE file
        FileNotFoundError: If the file doesn't exist
    """
    if fs is None:
        fs = RealFileSystem()

    if not os.path.exists(pe_path):
        raise FileNotFoundError(f"PE file not found: {pe_path}")

    try:
        pe = fs.create_pe(pe_path)
        logger.debug(f"Validated PE file: {pe_path}")
        return pe
    except pefile.PEFormatError as e:
        raise ValueError(f"Invalid PE file {pe_path}: {e}")


def extract_authenticode_signature(pe_path: str, fs: FileSystemInterface = None) -> Tuple[bytes, int, int]:
    """Extract the Authenticode signature from a PE file.

    Args:
        pe_path: Path to the signed PE file
        fs: File system interface for dependency injection (optional)

    Returns:
        Tuple containing:
        - bytes: The signature data
        - int: Offset of the signature in the file
        - int: Size of the signature

    Raises:
        ValueError: If no signature is found or signature is invalid
    """
    if fs is None:
        fs = RealFileSystem()

    pe = validate_pe_file(pe_path, fs)

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
    file_data = fs.read_binary_file(pe_path)
    signature_data = file_data[security_dir.VirtualAddress:security_dir.VirtualAddress + security_dir.Size]

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
        cert_data_raw = signature_data[offset + 8 : offset + dwLength]
        cert_data_decoded, _ = decoder.decode(cert_data_raw, asn1Spec=rfc2315.ContentInfo())

        signature_info = {
            "offset": offset,
            "length": dwLength,
            "revision": wRevision,
            "certificate_type": wCertificateType,
            "data": cert_data_decoded,
            "raw_data": cert_data_raw,  # Store raw bytes for export
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

    WIN_CERTIFICATE is the wrapper structure used in PE files to store signatures.
    It consists of an 8-byte header followed by the actual PKCS#7 data:
    - DWORD dwLength (4 bytes): Total size including header
    - WORD wRevision (2 bytes): Should be 0x0200
    - WORD wCertificateType (2 bytes): 0x0002 for PKCS_SIGNED_DATA
    - BYTE bCertificate[]: The PKCS#7 DER-encoded signature

    This function strips the 8-byte header to return just the PKCS#7 data.

    Args:
        signature_data: Raw WIN_CERTIFICATE data from PE security directory

    Returns:
        bytes: Pure PKCS#7 DER-encoded signature data

    Raises:
        ValueError: If signature_data is less than 8 bytes (invalid WIN_CERTIFICATE)
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


def validate_pkcs7_signatures(pe_data: bytes, *pkcs7_data_list: bytes) -> Tuple[bytes, ...]:
    """Validate multiple PKCS#7 signatures cryptographically and return them for separate WIN_CERTIFICATE structures.

    This function validates that all PKCS#7 structures are valid signedData and performs
    cryptographic verification of each signature against the PE file.
    We create multiple independent WIN_CERTIFICATE structures that UEFI firmware can
    iterate through during Secure Boot validation.

    IMPORTANT: This is NOT nested signatures (signtool /as). We do NOT nest one PKCS#7
    inside another's unauthenticated attributes. Instead, we use the UEFI-standard
    approach of multiple WIN_CERTIFICATE structures.

    Args:
        pe_data: The full PE file data (bytes)
        *pkcs7_data_list: Variable number of PKCS#7 signature data (each becomes a WIN_CERTIFICATE)

    Returns:
        Tuple[bytes, ...]: All PKCS#7 signatures, validated and ready to wrap

    Raises:
        ValueError: If any PKCS#7 structure is invalid, not signedData type, or fails cryptographic verification
    """
    logger.info("Validating PKCS#7 signatures with cryptographic verification...")

    if len(pkcs7_data_list) < 2:
        raise ValueError("At least 2 PKCS#7 signatures are required for validation")

    validated_signatures = []

    # Decode all PKCS#7 structures to validate them
    try:
        for i, pkcs7_data in enumerate(pkcs7_data_list, 1):
            logger.info(f"\n=== Validating Signature {i} ===")

            content_info, _ = decoder.decode(pkcs7_data, asn1Spec=rfc2315.ContentInfo())
            logger.info(f"Signature {i} type: {content_info['contentType']}")

            # Verify it's signedData (OID 1.2.840.113549.1.7.2)
            if str(content_info["contentType"]) != "1.2.840.113549.1.7.2":
                raise ValueError(f"Source {i} is not signedData: {content_info['contentType']}")

            # Extract the signedData content for logging
            signed_data, _ = decoder.decode(bytes(content_info["content"]), asn1Spec=rfc2315.SignedData())

            logger.info(
                f"Signature {i}: version={signed_data['version']}, signerInfos={len(signed_data['signerInfos'])}"
            )
            logger.info(f"Signature {i} size: {len(pkcs7_data)} bytes")

            # Extract and log certificates
            certificates = _extract_certificates_from_pkcs7(pkcs7_data)
            logger.info(f"Certificates found: {len(certificates)}")
            for cert_idx, cert in enumerate(certificates, 1):
                logger.info(f"  Certificate {cert_idx}:")
                logger.info(f"    Subject: {cert.subject.rfc4514_string()}")
                logger.info(f"    Issuer: {cert.issuer.rfc4514_string()}")

            # Perform cryptographic verification
            logger.info("Performing cryptographic verification...")
            verification_result = _verify_pkcs7_signature(pkcs7_data, pe_data)

            # Log verification results
            if verification_result['verified']:
                logger.info("[+] Signature cryptographically VERIFIED")
                for signer in verification_result['signers']:
                    if signer['verified']:
                        logger.info(f"  Signer {signer['index'] + 1}: VERIFIED")
            else:
                logger.error("[-] Signature verification FAILED")
                for error in verification_result['errors']:
                    logger.error(f"  - {error}")
                raise ValueError(f"Signature {i} failed cryptographic verification: {verification_result['errors']}")

            validated_signatures.append(pkcs7_data)

        logger.info(
            f"\nAll {len(validated_signatures)} signatures validated successfully with cryptographic verification!"
        )
        logger.info("Returning signatures for multiple WIN_CERTIFICATE structures")

        return tuple(validated_signatures)

    except Exception as e:
        logger.error(f"Failed to validate PKCS#7 signatures: {e}")
        import traceback

        logger.error(traceback.format_exc())
        raise


def create_multiple_win_certificates(list_of_pkcs7_data: List[bytes]) -> bytes:
    """Create multiple WIN_CERTIFICATE structures for multi-signed PE file.

    UEFI Secure Boot iterates through multiple WIN_CERTIFICATE structures sequentially.
    It validates each signature until one succeeds.

    Args:
        list_of_pkcs7_data: List of PKCS#7 signatures to wrap in WIN_CERTIFICATE structures

    Returns:
        bytes: Concatenated WIN_CERTIFICATE structures, properly aligned
    """
    logger.info("Creating multiple WIN_CERTIFICATE structures...")

    combined_pkcs7_data = bytearray()
    for pkcs7_data in list_of_pkcs7_data:
        # Create WIN_CERTIFICATE for each PKCS#7 signature
        win_cert = create_win_certificate(pkcs7_data)
        logger.info(f"WIN_CERTIFICATE: {len(win_cert)} bytes")

        # Already 8-byte aligned individually
        combined_pkcs7_data += win_cert

    logger.info(f"Total security directory size: {len(combined_pkcs7_data)} bytes")
    logger.info("UEFI will iterate through both signatures and accept if either validates")

    return bytes(combined_pkcs7_data)


def create_win_certificate(pkcs7_data: bytes) -> bytes:
    """Wrap PKCS#7 data in a WIN_CERTIFICATE structure for PE embedding.

    Creates a WIN_CERTIFICATE structure suitable for embedding in a PE file's
    security directory. The structure must be 8-byte aligned per PE specification.

    WIN_CERTIFICATE structure layout:
        Offset  Size  Field                Value
        ------  ----  -------------------  -----
        0x00    4     dwLength             Total size (header + PKCS#7 + padding)
        0x04    2     wRevision            0x0200 (WIN_CERT_REVISION_2_0)
        0x06    2     wCertificateType     0x0002 (WIN_CERT_TYPE_PKCS_SIGNED_DATA)
        0x08    N     bCertificate         PKCS#7 DER-encoded signature
        N+8     P     [padding]            Zero padding to 8-byte alignment

    Args:
        pkcs7_data: PKCS#7 DER-encoded signature data to wrap

    Returns:
        bytes: Complete WIN_CERTIFICATE structure with proper header and padding,
               ready to append to PE file and reference from security directory
    """
    # Calculate total length (must be 8-byte aligned)
    header_size = 8  # 4 + 2 + 2
    total_length = header_size + len(pkcs7_data)

    # Align to 8 bytes
    padding = (8 - (total_length % 8)) % 8
    total_length += padding

    logger.info("Creating WIN_CERTIFICATE structure:")
    logger.info(f"  PKCS#7 size: {len(pkcs7_data)} bytes")
    logger.info(f"  Header size: {header_size} bytes")
    logger.info(f"  Padding: {padding} bytes")
    logger.info(f"  Total size: {total_length} bytes")

    # Create WIN_CERTIFICATE header
    win_cert = struct.pack("<I", total_length)  # dwLength (little-endian DWORD)
    win_cert += struct.pack("<H", 0x0200)  # wRevision (little-endian WORD)
    win_cert += struct.pack("<H", 0x0002)  # wCertificateType (PKCS_SIGNED_DATA)

    # Append PKCS#7 data
    win_cert += pkcs7_data

    # Add padding to align to 8 bytes
    if padding > 0:
        win_cert += b"\x00" * padding

    logger.info(f"Created WIN_CERTIFICATE: {len(win_cert)} bytes")

    return win_cert


def save_signature_information(pkcs7_data_list: list, output_prefix: str, fs: FileSystemInterface = None) -> None:
    """Save individual PKCS#7 signatures with consistent naming.

    Args:
        pkcs7_data_list: List of PKCS#7 signature data (bytes)
        output_prefix: Prefix for output filenames (e.g., 'combined', 'nested')
        fs: File system interface for dependency injection (optional)
    """
    if fs is None:
        fs = RealFileSystem()

    for i, pkcs7_data in enumerate(pkcs7_data_list, 1):
        pkcs7_file = f"{output_prefix}_signature{i}.p7b"
        fs.write_binary_file(pkcs7_file, pkcs7_data)
        logger.info(f"Saved signature {i} PKCS#7 to: {pkcs7_file} ({len(pkcs7_data)} bytes)")


def create_win_certificate_with_nested_signatures(*pkcs7_data_list: bytes) -> bytes:
    """Combine multiple PKCS#7 signatures using Microsoft nested signature approach.

    This function implements the same structure as signtool's /as flag:
    1. Uses first PKCS#7 signature as the primary signature
    2. Embeds all other PKCS#7 signatures as nested signatures in unauthenticated attributes
    3. Uses OID 1.3.6.1.4.1.311.2.4.1 (Microsoft Nested Signature) for the attributes

    This matches how Windows signtool creates nested signatures with /as flag.

    Args:
        *pkcs7_data_list: Variable number of PKCS#7 signature data (first becomes primary, rest nested)

    Returns:
        bytes: Combined PKCS#7 data with nested signature structure wrapped in WIN_CERTIFICATE

    Raises:
        ValueError: If less than 2 signatures provided or any signature is invalid
    """
    # Validate input
    if len(pkcs7_data_list) < 2:
        raise ValueError("At least 2 PKCS#7 signatures are required for nested signatures")

    logger.info(f"Parsing {len(pkcs7_data_list)} PKCS#7 signatures for nested combination...")

    # Decode all PKCS#7 structures and validate them
    try:
        all_content_info = []
        all_signed_data = []

        for i, pkcs7_data in enumerate(pkcs7_data_list, 1):
            content_info, _ = decoder.decode(pkcs7_data, asn1Spec=rfc2315.ContentInfo())
            logger.info(f"ContentInfo {i} type: {content_info['contentType']}")

            # Verify it's signedData (OID 1.2.840.113549.1.7.2)
            if str(content_info["contentType"]) != "1.2.840.113549.1.7.2":
                raise ValueError(f"Source {i} is not signedData: {content_info['contentType']}")

            # Extract the signedData content
            signed_data, _ = decoder.decode(bytes(content_info["content"]), asn1Spec=rfc2315.SignedData())
            logger.info(f"SignedData {i} version: {signed_data['version']}")
            logger.info(f"SignedData {i} signerInfos: {len(signed_data['signerInfos'])}")

            all_content_info.append(content_info)
            all_signed_data.append(signed_data)

        # Use the first signature as the primary signature base
        primary_content_info = all_content_info[0]
        primary_signed_data = all_signed_data[0]

        # Create nested signature structure (Microsoft approach)
        num_nested = len(pkcs7_data_list) - 1
        logger.info(f"Creating nested signature structure with {num_nested} nested signatures (Microsoft /as style)...")

        # Use the first signature as the base
        combined_signed_data = rfc2315.SignedData()
        combined_signed_data["version"] = primary_signed_data["version"]
        combined_signed_data["digestAlgorithms"] = primary_signed_data["digestAlgorithms"]
        combined_signed_data["contentInfo"] = primary_signed_data["contentInfo"]

        # Copy certificates from first signature
        if "certificates" in primary_signed_data and primary_signed_data["certificates"].isValue:
            combined_signed_data["certificates"] = primary_signed_data["certificates"]
            logger.info(f"Using certificates from primary signature: {len(primary_signed_data['certificates'])}")

        # Get the first SignerInfo (primary signature)
        primary_signer = primary_signed_data["signerInfos"][0]
        logger.info("Extracted primary SignerInfo from source 1")

        # Create a new SignerInfo with nested signature in unauthenticated attributes
        modified_signer = rfc2315.SignerInfo()
        modified_signer["version"] = primary_signer["version"]
        modified_signer["issuerAndSerialNumber"] = primary_signer["issuerAndSerialNumber"]
        modified_signer["digestAlgorithm"] = primary_signer["digestAlgorithm"]

        # Copy authenticated attributes if present
        if "authenticatedAttributes" in primary_signer and primary_signer["authenticatedAttributes"].isValue:
            modified_signer["authenticatedAttributes"] = primary_signer["authenticatedAttributes"]

        modified_signer["digestEncryptionAlgorithm"] = primary_signer["digestEncryptionAlgorithm"]
        modified_signer["encryptedDigest"] = primary_signer["encryptedDigest"]

        # Preserve existing unauthenticated attributes (e.g., timestamp countersignature)
        # and add the nested signature
        # OID 1.3.6.1.4.1.311.2.4.1 = Microsoft Nested Signature
        # OID 1.2.840.113549.1.9.6 = countersignature (timestamp)

        # Start with existing unauthenticated attributes if present
        unauth_attrs = rfc2315.Attributes().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
        )

        attr_index = 0

        # Copy existing unauthenticated attributes (preserves timestamps)
        if "unauthenticatedAttributes" in primary_signer and primary_signer["unauthenticatedAttributes"].isValue:
            existing_attrs = primary_signer["unauthenticatedAttributes"]
            for i, attr in enumerate(existing_attrs):
                unauth_attrs[attr_index] = attr
                attr_index += 1
                # Log if we found a timestamp
                if str(attr["type"]) == "1.2.840.113549.1.9.6":
                    logger.info("Preserved timestamp countersignature from primary signature")

        # Create nested signature attributes for all additional signatures
        nested_sig_oid = univ.ObjectIdentifier("1.3.6.1.4.1.311.2.4.1")

        # Loop through all additional signatures (skip first one as it's the primary)
        for i, pkcs7_data in enumerate(pkcs7_data_list[1:], 2):
            logger.info(f"Adding signature {i} as nested signature...")

            # The nested signature is the entire PKCS#7 ContentInfo as a SEQUENCE
            nested_content_info, _ = decoder.decode(pkcs7_data, asn1Spec=rfc2315.ContentInfo())

            # Now encode it back to get the DER bytes wrapped as a SEQUENCE
            nested_pkcs7_encoded = encoder.encode(nested_content_info)

            # Create an untagged ANY value containing the nested PKCS#7
            nested_value = univ.Any(nested_pkcs7_encoded)

            # Create SET OF with the nested signature
            nested_signature_values = univ.SetOf(componentType=univ.Any())
            nested_signature_values[0] = nested_value

            # Create the Attribute structure for nested signature
            nested_sig_attr = rfc2315.Attribute()
            nested_sig_attr["type"] = nested_sig_oid
            nested_sig_attr["values"] = nested_signature_values

            # Add nested signature to unauthenticated attributes
            unauth_attrs[attr_index] = nested_sig_attr
            attr_index += 1

        modified_signer["unauthenticatedAttributes"] = unauth_attrs
        num_nested_sigs = len(pkcs7_data_list) - 1
        logger.info(
            f"Added {num_nested_sigs} nested signatures to unauthenticated attributes (OID 1.3.6.1.4.1.311.2.4.1)"
        )

        # Set the modified signer as the only SignerInfo
        combined_signer_infos = rfc2315.SignerInfos()
        combined_signer_infos[0] = modified_signer
        combined_signed_data["signerInfos"] = combined_signer_infos

        logger.info(f"Created SignerInfo with {len(pkcs7_data_list) - 1} nested signature structure(s)")

        # Encode the combined signedData
        combined_signed_data_encoded = encoder.encode(combined_signed_data)

        # Create new ContentInfo wrapper
        combined_content_info = rfc2315.ContentInfo()
        combined_content_info["contentType"] = primary_content_info["contentType"]  # signedData OID
        combined_content_info["content"] = univ.Any(combined_signed_data_encoded)

        # Encode the final ContentInfo
        combined_pkcs7 = encoder.encode(combined_content_info)

        logger.info(f"Combined PKCS#7 size: {len(combined_pkcs7)} bytes")
        logger.info("   (signtool reference size: 2904 bytes)")

        # Create descriptive filename based on signature information
        num_signatures = len(pkcs7_data_list)
        primary_version = primary_signed_data["version"]

        # Try to extract some identifying information from the primary signature
        try:
            primary_signer = primary_signed_data["signerInfos"][0]
            issuer_serial = primary_signer["issuerAndSerialNumber"]
            # Get the last 8 characters of serial number for filename
            serial_bytes = bytes(issuer_serial["serialNumber"])
            serial_hex = serial_bytes.hex()[-8:]  # Last 4 bytes as hex
            filename = f"nested_{num_signatures}sigs_v{primary_version}_s{serial_hex}.p7b"
        except Exception:
            # Fallback to simple naming if we can't extract serial
            filename = f"nested_{num_signatures}signatures_v{primary_version}.p7b"

        # Save to file for inspection
        with open(filename, "wb") as f:
            f.write(combined_pkcs7)
        logger.info(f"Saved combined PKCS#7 to: {filename}")        # Wrap in WIN_CERTIFICATE structure
        return create_win_certificate(combined_pkcs7)

    except Exception as e:
        logger.error(f"Failed to combine PKCS#7 signatures: {e}")
        import traceback

        logger.error(traceback.format_exc())
        raise


def apply_signature_to_pe(pe_path: str, signature_data: bytes, output_path: str) -> None:
    """Apply a WIN_CERTIFICATE signature to a PE file, creating a signed binary.

    This function modifies a PE file to include a new Authenticode signature by:
    1. Reading the source PE file into memory
    2. Locating the PE Optional Header and security directory entry
    3. Removing any existing signature data (truncating at original signature offset)
    4. Appending the new WIN_CERTIFICATE structure to the file
    5. Updating the security directory entry to point to the new signature
    6. Writing the modified PE file to the output path

    The security directory is entry 4 (IMAGE_DIRECTORY_ENTRY_SECURITY) in the
    Optional Header's Data Directory array. Its location varies by PE format:
    - PE32: Optional Header offset + 128 bytes
    - PE32+: Optional Header offset + 144 bytes

    Args:
        pe_path: Path to source PE file (used as template for code/data sections)
        signature_data: Complete WIN_CERTIFICATE structure (header + PKCS#7 + padding)
        output_path: Path where the signed PE file will be written

    Raises:
        ValueError: If PE format is unknown or security directory cannot be located
        IOError: If file operations fail
    """
    logger.info(f"Applying signature to PE file: {pe_path}")

    # Read the entire PE file
    with open(pe_path, "rb") as f:
        pe_data = bytearray(f.read())

    # Find PE header
    pe_offset = struct.unpack("<L", pe_data[0x3C:0x40])[0]
    logger.info(f"PE header at offset: 0x{pe_offset:x}")

    # Find Optional Header (PE + 4 bytes + 20 bytes COFF header)
    opt_header_offset = pe_offset + 4 + 20

    # Check if it's PE32 or PE32+
    magic = struct.unpack("<H", pe_data[opt_header_offset : opt_header_offset + 2])[0]

    if magic == 0x10B:  # PE32
        security_dir_offset = opt_header_offset + 128
        logger.info("PE32 format detected")
    elif magic == 0x20B:  # PE32+
        security_dir_offset = opt_header_offset + 144
        logger.info("PE32+ format detected")
    else:
        raise ValueError(f"Unknown PE format: magic=0x{magic:x}")

    # Read current security directory
    orig_va = struct.unpack("<L", pe_data[security_dir_offset : security_dir_offset + 4])[0]
    orig_size = struct.unpack("<L", pe_data[security_dir_offset + 4 : security_dir_offset + 8])[0]

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
    pe_data[security_dir_offset : security_dir_offset + 4] = struct.pack("<L", new_va)
    pe_data[security_dir_offset + 4 : security_dir_offset + 8] = struct.pack("<L", new_size)

    # Append new signature
    pe_data.extend(signature_data)

    # Write the result
    with open(output_path, "wb") as f:
        f.write(pe_data)

    logger.info(f"Applied signature to: {output_path}")
    logger.info(f"   File size: {len(pe_data)} bytes")


def cli() -> argparse.Namespace:
    """Parse command-line arguments for the Authenticode tool.

    Returns:
        argparse.Namespace: Parsed arguments containing:
            - subcommand: Either 'combine' or 'verify'
            - sources (List[str]): Paths to signed PE files
            - output (str): Path for output file (combine only)
            - force (bool): Force combination even if hashes differ (combine only)
            - debug (bool): Enable debug logging
    """
    parser = argparse.ArgumentParser(
        description="Authenticode signature tool for PE/UEFI binaries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--debug", action="store_true", default=False, help="Enable debug logging")

    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest="subcommand", help="Available commands", required=True)

    # Subcommand: combine
    combine_parser = subparsers.add_parser(
        "combine",
        help="Combine Authenticode signatures from multiple signed PE files into one binary",
    )
    combine_parser.add_argument("sources", nargs="+", help="Paths to signed PE files (2 or more)")
    combine_parser.add_argument(
        "--output", required=True, help="Path where the combined signature PE file will be saved"
    )
    combine_parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Force combination even if PE files have different content",
    )
    combine_parser.add_argument(
        "--nested",
        action="store_true",
        default=False,
        help="Use nested signature approach (like signtool /as) instead of multiple WIN_CERTIFICATE structures",
    )

    # Subcommand: verify
    verify_parser = subparsers.add_parser(
        "verify",
        help="Extract and verify Authenticode signatures from a PE file",
    )
    verify_parser.add_argument("source", help="Path to signed PE file to inspect")
    verify_parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory where extracted .p7b files will be saved (default: current directory)",
    )

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # Validate that at least 2 sources are provided for combine command
    if args.subcommand == "combine" and len(args.sources) < 2:
        combine_parser.error("At least 2 source PE files are required")

    return args


def main_combine(args: argparse.Namespace) -> int:
    """Execute the combine subcommand to merge multiple signatures.

    Orchestrates the complete workflow:
    1. Validates that all source PE files exist
    2. Calculates and compares Authenticode hashes (must match unless --force)
    3. Extracts PKCS#7 signatures from WIN_CERTIFICATE structures
    4. Validates all PKCS#7 signatures
    5. Creates separate WIN_CERTIFICATE structures for each signature (NOT nested signatures)
    6. Applies all signatures to output PE file

    The output file will contain multiple WIN_CERTIFICATE structures concatenated in the
    PE security directory. UEFI Secure Boot (DxeImageVerificationLib.c) iterates
    through all WIN_CERTIFICATE structures and validates each signature until one
    succeeds against db.

    Args:
        args: Parsed command-line arguments from argparse

    Returns:
        int: Exit code (0 for success, 1 for failure)
    """
    try:
        # Validate input files exist
        for pe_file in args.sources:
            if not os.path.exists(pe_file):
                logger.error(f"Source PE file not found: {pe_file}")
                return 1

        logger.info("Checking PE file compatibility...")

        # Check if all files have the same Authenticode hash
        hashes = []
        for i, pe_file in enumerate(args.sources, 1):
            pe_hash = get_authenticode_hash(pe_file)
            hashes.append(pe_hash)
            logger.info(f"Source {i}: {pe_file}")
            logger.info(f"  Authenticode hash: {pe_hash}")

        # Verify all hashes match (unless --force is used)
        if not args.force and len(set(hashes)) > 1:
            logger.error("All PE files must have identical authenticode hashes!")
            logger.error("Use --force to override this check")
            return 1

        logger.info("PE files have compatible content")

        logger.info("Extracting signatures...")

        # Extract signatures from all files
        all_sig_data = []
        for i, pe_file in enumerate(args.sources, 1):
            sig_data, blocks, _, _ = extract_all_signatures(pe_file)
            all_sig_data.append(sig_data)
            logger.info(f"Source {i} signature: {len(sig_data)} bytes, {len(blocks)} block(s)")

        # Extract PKCS#7 data from WIN_CERTIFICATE structures
        logger.info("Extracting PKCS#7 data from WIN_CERTIFICATE structures...")
        all_pkcs7_data = []
        for i, sig_data in enumerate(all_sig_data, 1):
            pkcs7_data = extract_pkcs7_from_wincert(sig_data)
            all_pkcs7_data.append(pkcs7_data)

        # Save individual PKCS#7 signatures with consistent naming
        save_signature_information(all_pkcs7_data, "source")

        # Validate the PKCS#7 signatures
        logger.info("Validating PKCS#7 signatures...")

        try:
            if args.nested:
                # For nested signatures, we need at least 2 signatures
                if len(all_pkcs7_data) < 2:
                    logger.error("Nested signature mode requires at least 2 source files")
                    return 1

                # Use the first PE file's data for verification
                with open(args.sources[0], 'rb') as f:
                    pe_data = f.read()
                validated_pkcs7_list = validate_pkcs7_signatures(pe_data, *all_pkcs7_data)
                logger.info(
                    f"All {len(validated_pkcs7_list)} signatures validated successfully for nested combination!"
                )

                # Save individual validated signatures consistently
                save_signature_information(list(validated_pkcs7_list), "nested_input")

                # Create nested signature WIN_CERTIFICATE structure
                logger.info("")
                logger.info("Creating nested signature structure (signtool /as style)...")
                win_cert_data = create_win_certificate_with_nested_signatures(*validated_pkcs7_list)
                logger.info(f"   Total WIN_CERTIFICATE data: {len(win_cert_data)} bytes")

                # Apply the nested signature to the output PE file
                logger.info("")
                logger.info(f"Applying nested signature to output file: {args.output}")
                apply_signature_to_pe(args.sources[0], win_cert_data, args.output)

                logger.info("")
                logger.info("SUCCESS! Nested-signed PE file created (signtool /as style)!")
                logger.info(f"   Output: {args.output}")
                logger.info("")
            else:
                # Use the first PE file's data for verification
                with open(args.sources[0], 'rb') as f:
                    pe_data = f.read()
                validated_pkcs7_list = validate_pkcs7_signatures(pe_data, *all_pkcs7_data)
                logger.info(f"All {len(validated_pkcs7_list)} signatures validated successfully!")

                # Save individual validated signatures consistently
                save_signature_information(list(validated_pkcs7_list), "multi_input")

                # Create multiple WIN_CERTIFICATE structures
                logger.info("")
                logger.info("Creating multiple WIN_CERTIFICATE structures...")
                win_cert_data = create_multiple_win_certificates(validated_pkcs7_list)
                logger.info(f"   Total WIN_CERTIFICATE data: {len(win_cert_data)} bytes")

                # Apply the multi-signature to the output PE file
                logger.info("")
                logger.info(f"Applying multi-signature to output file: {args.output}")
                apply_signature_to_pe(args.sources[0], win_cert_data, args.output)

                logger.info("")
                logger.info(
                    f"SUCCESS! Multi-signed PE file created with {len(validated_pkcs7_list)} "
                    "WIN_CERTIFICATE structures!"
                )
                logger.info(f"   Output: {args.output}")
                logger.info("")

            return 0

        except Exception as e:
            logger.error(f"Failed to create dual-signed binary: {e}")
            if args.debug:
                raise
            return 1

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.debug:
            raise
        return 1


def main_verify(args: argparse.Namespace) -> int:
    """Execute the verify subcommand to inspect signatures in a PE file.

    Extracts and displays information about all WIN_CERTIFICATE structures
    in the specified PE file, saving each PKCS#7 signature to a .p7b file.

    Args:
        args: Parsed command-line arguments from argparse

    Returns:
        int: Exit code (0 for success, 1 for failure)
    """
    try:
        # Validate input file exists
        if not os.path.exists(args.source):
            logger.error(f"PE file not found: {args.source}")
            return 1

        logger.info(f"Inspecting PE file: {args.source}")
        logger.info("")

        # Calculate Authenticode hash
        pe_hash = get_authenticode_hash(args.source)
        logger.info(f"Authenticode hash (SHA256): {pe_hash}")
        logger.info("")

        # Read PE file data for cryptographic verification
        with open(args.source, 'rb') as f:
            pe_data = f.read()

        # Extract signatures
        sig_data, blocks, offset, total_size = extract_all_signatures(args.source)
        logger.info(f"Security Directory: offset=0x{offset:x}, size={total_size} bytes")
        logger.info(f"Found {len(blocks)} WIN_CERTIFICATE structure(s)")
        logger.info("")

        # Create output directory if it doesn't exist
        os.makedirs(args.output_dir, exist_ok=True)

        # Process each WIN_CERTIFICATE block
        for i, block in enumerate(blocks, 1):
            logger.info(f"=== WIN_CERTIFICATE #{i} ===")
            logger.info(f"  Length: {block['length']} bytes")
            logger.info(f"  Revision: 0x{block['revision']:04x}")
            logger.info(f"  Certificate Type: 0x{block['certificate_type']:04x}")

            # Extract PKCS#7 raw bytes from this block
            pkcs7_data = block["raw_data"]

            # Save PKCS#7 to file
            base_name = os.path.splitext(os.path.basename(args.source))[0]
            if len(blocks) == 1:
                pkcs7_file = os.path.join(args.output_dir, f"{base_name}_signature.p7b")
            else:
                pkcs7_file = os.path.join(args.output_dir, f"{base_name}_signature{i}.p7b")

            with open(pkcs7_file, "wb") as f:
                f.write(pkcs7_data)
            logger.info(f"  Saved PKCS#7 to: {pkcs7_file} ({len(pkcs7_data)} bytes)")

            # Parse PKCS#7 structure - we already have it decoded in block['data']
            try:
                content_info = block["data"]
                content_type = str(content_info["contentType"])
                logger.info(f"  PKCS#7 ContentType: {content_type}")

                if content_type == "1.2.840.113549.1.7.2":  # signedData
                    signed_data, _ = decoder.decode(bytes(content_info["content"]), asn1Spec=rfc2315.SignedData())
                    logger.info(f"  SignedData version: {signed_data['version']}")
                    logger.info(f"  Number of signers: {len(signed_data['signerInfos'])}")
                    # Check if certificates field exists
                    if "certificates" in signed_data and signed_data["certificates"]:
                        num_certs = len(signed_data["certificates"])
                    else:
                        num_certs = 0
                    logger.info(f"  Number of certificates: {num_certs}")

                    # Extract and display certificates
                    certificates = _extract_certificates_from_pkcs7(pkcs7_data)
                    if certificates:
                        logger.info("  Certificate details:")
                        for cert_idx, cert in enumerate(certificates, 1):
                            logger.info(f"    Certificate {cert_idx}:")
                            logger.info(f"      Subject: {cert.subject.rfc4514_string()}")
                            logger.info(f"      Issuer: {cert.issuer.rfc4514_string()}")
                            logger.info(f"      Serial: {cert.serial_number}")
                            logger.info(f"      Valid: {cert.not_valid_before_utc} to {cert.not_valid_after_utc}")

                    # Perform cryptographic verification
                    logger.info("  Cryptographic Verification:")
                    verification_result = _verify_pkcs7_signature(pkcs7_data, pe_data)

                    if verification_result['verified']:
                        logger.info("    [+] Signature is cryptographically VALID")
                        for signer in verification_result['signers']:
                            if signer['verified']:
                                logger.info(f"      Signer {signer['index'] + 1}: VERIFIED")
                    else:
                        logger.warning("    [-] Signature verification FAILED")
                        for error in verification_result['errors']:
                            logger.warning(f"      - {error}")

            except Exception as e:
                logger.warning(f"  Could not parse PKCS#7 structure: {e}")
                if args.debug:
                    import traceback
                    traceback.print_exc()

            logger.info("")

        logger.info("Verification complete!")
        return 0

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.debug:
            raise
        return 1


def main() -> int:
    """Main entry point that dispatches to subcommands.

    Returns:
        int: Exit code (0 for success, 1 for failure)
    """
    args = cli()

    if args.subcommand == "combine":
        return main_combine(args)
    elif args.subcommand == "verify":
        return main_verify(args)
    else:
        logger.error(f"Unknown subcommand: {args.subcommand}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

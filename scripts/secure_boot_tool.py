# @file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Secure Boot Tool for analyzing and extracting certificates from signature databases.

This tool provides functionality to:
1. Describe the contents of secure boot signature databases (signed and unsigned)
2. Extract certificates from signature databases and save them as individual files
3. Generate detailed reports about the certificates and their properties

The tool can handle both signed authenticated variables and unsigned signature databases.
"""

import argparse
import hashlib
import json
import logging
import pathlib
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from edk2toollib.uefi.authenticated_variables_structure_support import (
    EfiSignatureDatabase,
    EfiSignatureDataEfiCertSha256,
    EfiSignatureDataEfiCertX509,
    EfiVariableAuthentication2,
)
from utility_functions import (
    SVN_OWNER_GUID,
    SvnData,
    get_certificates,
    get_signed_payload_receipt,
    get_unsigned_payload_receipt,
)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def extract_certificates_from_database(
    signature_database: EfiSignatureDatabase,
    output_dir: pathlib.Path,
    prefix: str = ""
) -> List[Dict[str, Any]]:
    """Extract X.509 certificates from a signature database and save them as individual files.
    
    Args:
        signature_database (EfiSignatureDatabase): The signature database to process
        output_dir (pathlib.Path): Directory to save extracted certificates
        prefix (str): Optional prefix for certificate filenames
        
    Returns:
        List[Dict[str, Any]]: List of certificate information dictionaries
    """
    extracted_certs = []
    extracted_hashes = []
    cert_counter = 1
    hash_counter = 1

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    for signature_list in signature_database.esl_list:
        for signature_data in signature_list.signature_data_list:
            if isinstance(signature_data, EfiSignatureDataEfiCertX509):
                try:
                    # Parse the certificate
                    cert = x509.load_der_x509_certificate(signature_data.signature_data)

                    # Generate certificate information
                    subject = cert.subject.rfc4514_string()
                    issuer = cert.issuer.rfc4514_string()
                    serial_number = format(cert.serial_number, 'x').upper()
                    thumbprint_sha1 = hashlib.sha1(signature_data.signature_data).hexdigest().upper()
                    thumbprint_sha256 = hashlib.sha256(signature_data.signature_data).hexdigest().upper()

                    # Create a safe filename from subject common name or use counter
                    try:
                        cn = None
                        for attribute in cert.subject:
                            if attribute.oid._name == 'commonName':
                                cn = attribute.value
                                break

                        if cn:
                            # Clean up the common name for use as filename
                            safe_name = "".join(c for c in cn if c.isalnum() or c in (' ', '-', '_')).rstrip()
                            safe_name = safe_name.replace(' ', '_')
                            filename = f"{prefix}{safe_name}_{thumbprint_sha1[:8]}.der"
                        else:
                            filename = f"{prefix}cert_{cert_counter:03d}_{thumbprint_sha1[:8]}.der"
                    except Exception:
                        filename = f"{prefix}cert_{cert_counter:03d}_{thumbprint_sha1[:8]}.der"

                    # Save certificate as DER file
                    cert_path = output_dir / filename
                    with open(cert_path, "wb") as f:
                        f.write(signature_data.signature_data)

                    # Save certificate as PEM file as well
                    pem_filename = filename.replace('.der', '.pem')
                    pem_path = output_dir / pem_filename
                    with open(pem_path, "wb") as f:
                        f.write(cert.public_bytes(serialization.Encoding.PEM))

                    cert_info = {
                        "certificate_number": cert_counter,
                        "subject": subject,
                        "issuer": issuer,
                        "serial_number": serial_number,
                        "thumbprint_sha1": thumbprint_sha1,
                        "thumbprint_sha256": thumbprint_sha256,
                        "signature_owner": str(signature_data.signature_owner),
                        "not_valid_before": cert.not_valid_before_utc.isoformat(),
                        "not_valid_after": cert.not_valid_after_utc.isoformat(),
                        "der_file": str(cert_path),
                        "pem_file": str(pem_path),
                        "der_size": len(signature_data.signature_data)
                    }

                    extracted_certs.append(cert_info)
                    cert_counter += 1

                    logger.info(f"Extracted certificate: {filename}")

                except Exception as e:
                    logger.error(f"Failed to process certificate {cert_counter}: {e}")
                    cert_counter += 1

            elif isinstance(signature_data, EfiSignatureDataEfiCertSha256):
                # Handle SHA256 hashes (not certificates, but document them)
                hash_value = signature_data.signature_data.hex().upper()

                # Check if this is an SVN entry
                if signature_data.signature_owner == SVN_OWNER_GUID:
                    try:
                        svn_data = SvnData.from_bytes(signature_data.signature_data)
                        hash_info = {
                            "hash_number": hash_counter,
                            "hash_type": "svn",
                            "hash_value": hash_value,
                            "signature_owner": str(signature_data.signature_owner),
                            "svn_data": {
                                "version": svn_data.version,
                                "application_guid": str(svn_data.application_guid),
                                "major_svn": svn_data.svn.major_svn,
                                "minor_svn": svn_data.svn.minor_svn,
                                "combined_svn": svn_data.svn.as_uint32
                            }
                        }
                        extracted_hashes.append(hash_info)
                        logger.info(f"Found SVN entry: {svn_data}")
                    except Exception as e:
                        # If SVN parsing fails, treat as regular hash
                        hash_info = {
                            "hash_number": hash_counter,
                            "hash_type": "sha256",
                            "hash_value": hash_value,
                            "signature_owner": str(signature_data.signature_owner)
                        }
                        extracted_hashes.append(hash_info)
                        logger.warning(f"Failed to parse SVN data: {e}")
                else:
                    hash_info = {
                        "hash_number": hash_counter,
                        "hash_type": "sha256",
                        "hash_value": hash_value,
                        "signature_owner": str(signature_data.signature_owner)
                    }
                    extracted_hashes.append(hash_info)
                    logger.info(f"Found SHA256 hash: {hash_value} (Owner: {signature_data.signature_owner})")

                hash_counter += 1

    # Return both certificates and hashes
    return {"certificates": extracted_certs, "hashes": extracted_hashes}


def describe_and_extract_signed_database(file_path: pathlib.Path, output_dir: pathlib.Path) -> Dict[str, Any]:
    """Process a signed signature database file.
    
    Args:
        file_path (pathlib.Path): Path to the signed database file
        output_dir (pathlib.Path): Directory for output files
        
    Returns:
        Dict[str, Any]: Complete analysis results
    """
    logger.info(f"Processing signed database: {file_path}")

    # Get the basic receipt information
    receipt = get_signed_payload_receipt(file_path)

    # Extract the signature database for certificate extraction
    with open(file_path, "rb") as f:
        auth_var = EfiVariableAuthentication2(decodefs=f)
        signature_database = auth_var.sig_list_payload

    # Create subdirectory for this file's certificates
    file_output_dir = output_dir / f"{file_path.stem}_certificates"
      # Extract certificates and hashes
    extraction_result = extract_certificates_from_database(
        signature_database,
        file_output_dir,
        f"{file_path.stem}_"
    )

    extracted_certs = extraction_result["certificates"]
    extracted_hashes = extraction_result["hashes"]

    # Get signing certificates from the authenticated variable
    signing_certs = get_certificates(auth_var)
    signing_cert_info = []

    if signing_certs:
        signing_cert_dir = output_dir / f"{file_path.stem}_signing_certificates"
        signing_cert_dir.mkdir(parents=True, exist_ok=True)

        for i, cert in enumerate(signing_certs, 1):
            if hasattr(cert, 'public_bytes'):  # Real certificate
                # Save signing certificate
                signing_cert_path = signing_cert_dir / f"signing_cert_{i:02d}.der"
                with open(signing_cert_path, "wb") as f:
                    f.write(cert.public_bytes(serialization.Encoding.DER))

                # Save as PEM too
                pem_path = signing_cert_dir / f"signing_cert_{i:02d}.pem"
                with open(pem_path, "wb") as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))

                signing_cert_info.append({
                    "certificate_number": i,
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "serial_number": format(cert.serial_number, 'x').upper(),
                    "thumbprint_sha1": hashlib.sha1(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper(),
                    "thumbprint_sha256": hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper(),
                    "der_file": str(signing_cert_path),
                    "pem_file": str(pem_path)
                })
            else:  # Empty certificate
                signing_cert_info.append({
                    "certificate_number": i,
                    "subject": "EMPTY PKCS7 SIGNATURE",
                    "issuer": "EMPTY PKCS7 SIGNATURE"
                })

    # Combine all information
    result = {
        **receipt,
        "extracted_certificates": extracted_certs,
        "extracted_hashes": extracted_hashes,
        "signing_certificates": signing_cert_info,
        "certificate_count": len(extracted_certs),
        "hash_count": len(extracted_hashes),
        "signing_certificate_count": len(signing_cert_info),
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "certificate_output_directory": str(file_output_dir)
    }

    return result


def describe_and_extract_unsigned_database(file_path: pathlib.Path, output_dir: pathlib.Path) -> Dict[str, Any]:
    """Process an unsigned signature database file.
    
    Args:
        file_path (pathlib.Path): Path to the unsigned database file
        output_dir (pathlib.Path): Directory for output files
        
    Returns:
        Dict[str, Any]: Complete analysis results
    """
    logger.info(f"Processing unsigned database: {file_path}")

    # Get the basic receipt information
    receipt = get_unsigned_payload_receipt(file_path)

    # Load the signature database for certificate extraction
    with open(file_path, "rb") as f:
        signature_database = EfiSignatureDatabase(filestream=f)

    # Create subdirectory for this file's certificates
    file_output_dir = output_dir / f"{file_path.stem}_certificates"
      # Extract certificates and hashes
    extraction_result = extract_certificates_from_database(
        signature_database,
        file_output_dir,
        f"{file_path.stem}_"
    )

    extracted_certs = extraction_result["certificates"]
    extracted_hashes = extraction_result["hashes"]

    # Combine all information
    result = {
        **receipt,
        "extracted_certificates": extracted_certs,
        "extracted_hashes": extracted_hashes,
        "certificate_count": len(extracted_certs),
        "hash_count": len(extracted_hashes),
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "certificate_output_directory": str(file_output_dir)
    }

    return result


def generate_summary_report(results: List[Dict[str, Any]], output_path: pathlib.Path) -> None:
    """Generate a summary report of all processed files.
    
    Args:
        results (List[Dict[str, Any]]): List of analysis results
        output_path (pathlib.Path): Path for the summary report
    """
    summary = {
        "summary": {
            "total_files_processed": len(results),
            "total_certificates_extracted": sum(r.get("certificate_count", 0) for r in results),
            "analysis_timestamp": datetime.now(timezone.utc).isoformat()
        },
        "files": results
    }

    with open(output_path, "w") as f:
        json.dump(summary, f, indent=2)

    logger.info(f"Summary report saved to: {output_path}")


def main() -> None:
    """Main function for the secure boot tool."""
    parser = argparse.ArgumentParser(
        description="Secure Boot Tool for analyzing and extracting certificates from signature databases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single signed database file
  python secure_boot_tool.py analyze signed_db.authvar.bin --output-dir ./output

  # Analyze an unsigned database file
  python secure_boot_tool.py analyze unsigned_db.bin --output-dir ./output --unsigned

  # Analyze multiple files in a directory
  python secure_boot_tool.py analyze-dir ./databases --output-dir ./output

  # Extract only certificates without full analysis
  python secure_boot_tool.py extract-certs database.bin --output-dir ./certs
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze single file command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a single signature database file")
    analyze_parser.add_argument("file", type=pathlib.Path, help="Path to the signature database file")
    analyze_parser.add_argument("--output-dir", "-o", type=pathlib.Path, default="./output",
                               help="Output directory for extracted certificates and reports")
    analyze_parser.add_argument("--unsigned", action="store_true",
                               help="Treat the file as an unsigned signature database")
    analyze_parser.add_argument("--json-output", type=pathlib.Path,
                               help="Save analysis results as JSON to specified file")

    # Analyze directory command
    analyze_dir_parser = subparsers.add_parser("analyze-dir", help="Analyze all signature database files in a directory")
    analyze_dir_parser.add_argument("directory", type=pathlib.Path, help="Directory containing signature database files")
    analyze_dir_parser.add_argument("--output-dir", "-o", type=pathlib.Path, default="./output",
                                   help="Output directory for extracted certificates and reports")
    analyze_dir_parser.add_argument("--pattern", default="*.bin", help="File pattern to match (default: *.bin)")
    analyze_dir_parser.add_argument("--unsigned", action="store_true",
                                   help="Treat all files as unsigned signature databases")

    # Extract certificates only command
    extract_parser = subparsers.add_parser("extract-certs", help="Extract certificates only (no full analysis)")
    extract_parser.add_argument("file", type=pathlib.Path, help="Path to the signature database file")
    extract_parser.add_argument("--output-dir", "-o", type=pathlib.Path, default="./certificates",
                               help="Output directory for extracted certificates")
    extract_parser.add_argument("--unsigned", action="store_true",
                               help="Treat the file as an unsigned signature database")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        if args.command == "analyze":
            if not args.file.exists():
                logger.error(f"File not found: {args.file}")
                return 1

            # Analyze single file
            if args.unsigned:
                result = describe_and_extract_unsigned_database(args.file, args.output_dir)
            else:
                result = describe_and_extract_signed_database(args.file, args.output_dir)

            # Save individual file report
            if args.json_output:
                output_path = args.json_output
            else:
                output_path = args.output_dir / f"{args.file.stem}_analysis.json"

            args.output_dir.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(result, f, indent=2)

            logger.info(f"Analysis complete. Results saved to: {output_path}")
            logger.info(f"Certificates extracted: {result.get('certificate_count', 0)}")

        elif args.command == "analyze-dir":
            if not args.directory.exists():
                logger.error(f"Directory not found: {args.directory}")
                return 1

            # Find all matching files
            files = list(args.directory.glob(args.pattern))
            if not files:
                logger.error(f"No files matching pattern '{args.pattern}' found in {args.directory}")
                return 1

            logger.info(f"Found {len(files)} files to process")

            results = []
            for file_path in files:
                try:
                    logger.info(f"Processing: {file_path}")
                    if args.unsigned:
                        result = describe_and_extract_unsigned_database(file_path, args.output_dir)
                    else:
                        result = describe_and_extract_signed_database(file_path, args.output_dir)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Failed to process {file_path}: {e}")
                    continue

            # Generate summary report
            summary_path = args.output_dir / "analysis_summary.json"
            generate_summary_report(results, summary_path)

            total_certs = sum(r.get("certificate_count", 0) for r in results)
            logger.info(f"Batch analysis complete. Processed {len(results)} files, extracted {total_certs} certificates")

        elif args.command == "extract-certs":
            if not args.file.exists():
                logger.error(f"File not found: {args.file}")
                return 1

            # Extract certificates only
            if args.unsigned:
                with open(args.file, "rb") as f:
                    signature_database = EfiSignatureDatabase(filestream=f)
            else:
                with open(args.file, "rb") as f:
                    auth_var = EfiVariableAuthentication2(decodefs=f)
                    signature_database = auth_var.sig_list_payload

            extracted_certs = extract_certificates_from_database(
                signature_database,
                args.output_dir,
                f"{args.file.stem}_"
            )

            logger.info(f"Certificate extraction complete. Extracted {len(extracted_certs)} certificates to: {args.output_dir}")

        return 0

    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

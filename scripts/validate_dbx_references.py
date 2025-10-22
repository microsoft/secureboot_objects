# @file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Script to validate that DBX JSON files reference existing certificate files.

This script reads the latest DBX JSON file and validates that all certificate
files referenced in the "certificates" array actually exist in the
PreSignedObjects/DBX/Certificates folder.
"""
import argparse
import json
import logging
import pathlib
import sys
from typing import List


def get_latest_dbx_info_file(dbx_directory: pathlib.Path) -> pathlib.Path:
    """Get the latest DBX info JSON file from the specified directory.

    Args:
        dbx_directory (pathlib.Path): The directory path to search for DBX JSON files.

    Returns:
        pathlib.Path: The path to the latest DBX info JSON file.

    Raises:
        FileNotFoundError: If no DBX info JSON files are found in the specified directory.
    """
    # Look specifically for dbx_info_msft_*.json files
    dbx_files = list(dbx_directory.glob("dbx_info_msft_*.json"))
    if not dbx_files:
        raise FileNotFoundError("No DBX info JSON files found in the specified directory.")

    # Check if we have the standard latest file
    latest_file = dbx_directory / "dbx_info_msft_latest.json"
    if latest_file.exists():
        return latest_file

    # Fall back to parsing date components from filenames (month_day_year format)
    # Filter out any files that don't follow the date pattern
    dated_files = []
    for f in dbx_files:
        try:
            # Try to parse the last 3 parts as integers (month, day, year)
            parts = f.stem.split("_")
            if len(parts) >= 6:  # dbx_info_msft_month_day_year
                list(map(int, parts[-3:]))  # This will raise ValueError if not all integers
                dated_files.append(f)
        except (ValueError, IndexError):
            # Skip files that don't follow the date pattern
            continue

    if not dated_files:
        # If no dated files, just return the first available file
        return dbx_files[0]

    # Return the file with the latest date
    try:
        latest_file = max(dated_files, key=lambda f: list(map(int, f.stem.split("_")[-3:])))
        return latest_file
    except (ValueError, IndexError) as e:
        raise FileNotFoundError(f"Could not parse date from DBX info filenames: {e}")


def validate_certificate_references(dbx_json_path: pathlib.Path, certificates_dir: pathlib.Path) -> List[str]:
    """Validate that certificate references in DBX JSON exist in the certificates directory.

    Args:
        dbx_json_path (pathlib.Path): Path to the DBX JSON file
        certificates_dir (pathlib.Path): Path to the certificates directory

    Returns:
        List[str]: List of error messages for missing certificates (empty if all exist)

    Raises:
        FileNotFoundError: If the DBX JSON file doesn't exist
        json.JSONDecodeError: If the JSON file is malformed
    """
    errors = []

    # Load the DBX JSON file
    with open(dbx_json_path, 'r') as f:
        dbx_data = json.load(f)

    # Check if certificates section exists
    if 'certificates' not in dbx_data:
        logging.info("No 'certificates' section found in DBX JSON file - validation passed")
        return errors

    certificates = dbx_data['certificates']
    if not certificates:
        logging.info("Empty 'certificates' section found in DBX JSON file - validation passed")
        return errors

    logging.info(f"Found {len(certificates)} certificate references to validate")

    # Validate each certificate reference
    for i, cert_entry in enumerate(certificates):
        if 'value' not in cert_entry:
            errors.append(f"Certificate entry {i} missing 'value' field")
            continue

        cert_filename = cert_entry['value']
        cert_path = certificates_dir / cert_filename

        if not cert_path.exists():
            errors.append(f"Certificate file '{cert_filename}' referenced in JSON but not found in {certificates_dir}")
            logging.error(f"Missing certificate: {cert_filename}")
        else:
            logging.info(f"Certificate found: {cert_filename}")

    return errors


def main() -> None:
    """Main function to handle command-line arguments and validate DBX certificate references."""
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    parser = argparse.ArgumentParser(
        description="Validate that DBX JSON files reference existing certificate files."
    )
    parser.add_argument(
        "dbx_directory",
        help="Path to the PreSignedObjects/DBX directory",
        type=pathlib.Path
    )
    parser.add_argument(
        "--json-file",
        help="Specific DBX JSON file to validate (default: latest dbx_info_msft_*.json)",
        type=pathlib.Path
    )

    args = parser.parse_args()

    # Validate input directory
    if not args.dbx_directory.is_dir():
        logging.error(f"DBX directory does not exist: {args.dbx_directory}")
        sys.exit(1)

    certificates_dir = args.dbx_directory / "Certificates"
    if not certificates_dir.is_dir():
        logging.error(f"Certificates directory does not exist: {certificates_dir}")
        sys.exit(1)

    # Determine which JSON file to validate
    if args.json_file:
        dbx_json_path = args.json_file
        if not dbx_json_path.is_absolute():
            dbx_json_path = args.dbx_directory / dbx_json_path
    else:
        try:
            dbx_json_path = get_latest_dbx_info_file(args.dbx_directory)
            logging.info(f"Using latest DBX JSON file: {dbx_json_path.name}")
        except FileNotFoundError as e:
            logging.error(f"No DBX JSON files found in {args.dbx_directory}: {e}")
            sys.exit(1)

    # Validate the JSON file exists
    if not dbx_json_path.exists():
        logging.error(f"DBX JSON file does not exist: {dbx_json_path}")
        sys.exit(1)

    try:
        # Perform validation
        errors = validate_certificate_references(dbx_json_path, certificates_dir)

        if errors:
            logging.error("Certificate reference validation failed:")
            for error in errors:
                logging.error(f"  - {error}")

            # List available certificate files for debugging
            available_certs = list(certificates_dir.glob("*"))
            if available_certs:
                logging.info("Available certificate files:")
                for cert_file in available_certs:
                    logging.info(f"  - {cert_file.name}")
            else:
                logging.warning("No certificate files found in the certificates directory")

            sys.exit(1)
        else:
            logging.info("All certificate references validated successfully!")

    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Error reading DBX JSON file: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error during validation: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


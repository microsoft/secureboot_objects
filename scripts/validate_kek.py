"""Validate KEK update file(s) and generate a JSON report.

This script validates authenticated variable files - either a single file or all
files in a specified folder - and generates a JSON report with validation results.
"""

import argparse
import hashlib
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

# Import validation functions from auth_var_tool
sys.path.insert(0, str(Path(__file__).parent))
# Import the verify function from auth_var_tool
from auth_var_tool import verify_variable
from edk2toollib.uefi.authenticated_variables_structure_support import EfiVariableAuthentication2

# Standard KEK parameters
KEK_NAME = "KEK"
KEK_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
KEK_ATTRIBUTES = "NV,BS,RT,AT,AP"

# Expected payload hash for Microsoft 2023 KEK (EFI Signature List with x.509)
EXPECTED_PAYLOAD_HASH = "5b85333c009d7ea55cbb6f11a5c2ff45ee1091a968504c929aed25c84674962f"


def validate_single_kek(
    kek_file: Path,
    quiet: bool = False
) -> dict:
    """Validate a single KEK update file.

    Args:
        kek_file: Path to KEK update file
        quiet: If True, suppress validation output from the verification process

    Returns:
        dict: Validation result for the file
    """
    logging.info(f"Validating: {kek_file.name}")

    file_result = {
        "filename": kek_file.name,
        "path": str(kek_file),
        "valid": False,
        "payload_hash_valid": False,
        "error": None,
        "warnings": [],
        "details": {}
    }

    try:
        # First, parse the authenticated variable to check payload hash
        with open(kek_file, 'rb') as f:
            auth_var = EfiVariableAuthentication2(decodefs=f)
            payload = auth_var.payload
            payload_hash = hashlib.sha256(payload).hexdigest()

            file_result["payload_hash"] = payload_hash
            file_result["payload_size"] = len(payload)
            file_result["payload_hash_valid"] = (payload_hash.lower() == EXPECTED_PAYLOAD_HASH.lower())

            if not file_result["payload_hash_valid"]:
                warning_msg = f"Payload hash mismatch: expected {EXPECTED_PAYLOAD_HASH}, got {payload_hash}"
                file_result["warnings"].append(warning_msg)
                logging.warning("  [!] Payload hash mismatch!")
                logging.warning(f"      Expected: {EXPECTED_PAYLOAD_HASH}")
                logging.warning(f"      Got:      {payload_hash}")

        # Validate the file using auth_var_tool.verify_variable
        # Create a namespace object with the required arguments
        import argparse
        verify_args = argparse.Namespace(
            authvar_file=str(kek_file),
            var_name=KEK_NAME,
            var_guid=KEK_GUID,
            attributes=KEK_ATTRIBUTES,
            verbose=False
        )

        # Capture logger output if in quiet mode
        if quiet:
            # Temporarily increase logger level to suppress INFO messages
            original_level = logging.root.level
            logging.root.setLevel(logging.ERROR)

        try:
            # verify_variable returns 0 for success, 1 for failure
            exit_code = verify_variable(verify_args)
            file_result["valid"] = (exit_code == 0)

            if not file_result["valid"]:
                file_result["warnings"].append("Signature verification failed")
        finally:
            if quiet:
                # Restore original logger level
                logging.root.setLevel(original_level)

        # Store basic details
        file_result["details"] = {
            "verified": file_result["valid"]
        }

        # Display results
        sig_status = "VALID" if file_result["valid"] else "INVALID"
        payload_status = "True" if file_result["payload_hash_valid"] else "False"

        logging.info(f"  Cryptographic Signature: {sig_status}")
        logging.info(f"  Expected Payload: {payload_status}\n")

    except Exception as e:
        file_result["error"] = str(e)
        logging.error(f"  [X] ERROR: {e}\n")

    return file_result


def validate_kek_folder(
    folder_path: Path,
    output_file: Path = None,
    quiet: bool = False,
    recursive: bool = False
) -> dict:
    """Validate all .bin files in the specified folder.

    Args:
        folder_path: Path to folder containing KEK update files
        output_file: Optional path to output JSON file
        quiet: If True, suppress validation output from the prototype
        recursive: If True, process subdirectories recursively

    Returns:
        dict: Validation results
    """
    results = {
        "validation_date": datetime.now(timezone.utc).isoformat(),
        "folder": str(folder_path),
        "parameters": {
            "var_name": KEK_NAME,
            "var_guid": KEK_GUID,
            "attributes": KEK_ATTRIBUTES
        },
        "files": {},
        "by_manufacturer": {}
    }

    # Find all .bin files (recursively if requested)
    if recursive:
        bin_files = sorted(folder_path.rglob("*.bin"))
    else:
        bin_files = sorted(folder_path.glob("*.bin"))

    if not bin_files:
        logging.warning(f"No .bin files found in {folder_path}")
        # Initialize empty summary for consistency
        results["summary"] = {
            "total": 0,
            "valid": 0,
            "invalid": 0,
            "manufacturers": 0
        }
        return results

    logging.info(f"Found {len(bin_files)} files to validate\n")

    # Validate each file
    for bin_file in bin_files:
        # Determine manufacturer (relative path from base folder)
        relative_path = bin_file.relative_to(folder_path)
        if len(relative_path.parts) > 1:
            manufacturer = relative_path.parts[0]
        else:
            manufacturer = "root"

        logging.info(f"Validating: {relative_path}")

        file_result = {
            "filename": bin_file.name,
            "relative_path": str(relative_path),
            "manufacturer": manufacturer,
            "path": str(bin_file),
            "valid": False,
            "payload_hash_valid": False,
            "error": None,
            "warnings": [],
            "details": {}
        }

        try:
            # First, parse the authenticated variable to check payload hash
            with open(bin_file, 'rb') as f:
                auth_var = EfiVariableAuthentication2(decodefs=f)
                payload = auth_var.payload
                payload_hash = hashlib.sha256(payload).hexdigest()

                file_result["payload_hash"] = payload_hash
                file_result["payload_size"] = len(payload)
                file_result["payload_hash_valid"] = (payload_hash.lower() == EXPECTED_PAYLOAD_HASH.lower())

                if not file_result["payload_hash_valid"]:
                    warning_msg = f"Payload hash mismatch: expected {EXPECTED_PAYLOAD_HASH}, got {payload_hash}"
                    file_result["warnings"].append(warning_msg)
                    logging.warning("  [!] Payload hash mismatch!")
                    logging.warning(f"      Expected: {EXPECTED_PAYLOAD_HASH}")
                    logging.warning(f"      Got:      {payload_hash}")

            # Validate the file using auth_var_tool.verify_variable
            # Create a namespace object with the required arguments
            import argparse
            verify_args = argparse.Namespace(
                authvar_file=str(bin_file),
                var_name=KEK_NAME,
                var_guid=KEK_GUID,
                attributes=KEK_ATTRIBUTES,
                verbose=False
            )

            # Capture logger output if in quiet mode
            if quiet:
                # Temporarily increase logger level to suppress INFO messages
                original_level = logging.root.level
                logging.root.setLevel(logging.ERROR)

            try:
                # verify_variable returns 0 for success, 1 for failure
                exit_code = verify_variable(verify_args)
                file_result["valid"] = (exit_code == 0)

                if not file_result["valid"]:
                    file_result["warnings"].append("Signature verification failed")
            finally:
                if quiet:
                    # Restore original logger level
                    logging.root.setLevel(original_level)

            # Store basic details
            file_result["details"] = {
                "verified": file_result["valid"]
            }

            # Display results
            sig_status = "VALID" if file_result["valid"] else "INVALID"
            payload_status = "True" if file_result["payload_hash_valid"] else "False"

            logging.info(f"  Cryptographic Signature: {sig_status}")
            logging.info(f"  Expected Payload: {payload_status}\n")

        except Exception as e:
            file_result["error"] = str(e)
            logging.error(f"  [X] ERROR: {e}")

        results["files"][str(relative_path)] = file_result

        # Add to manufacturer grouping
        if manufacturer not in results["by_manufacturer"]:
            results["by_manufacturer"][manufacturer] = {
                "files": [],
                "valid": 0,
                "invalid": 0
            }
        results["by_manufacturer"][manufacturer]["files"].append(str(relative_path))
        if file_result["valid"]:
            results["by_manufacturer"][manufacturer]["valid"] += 1
        else:
            results["by_manufacturer"][manufacturer]["invalid"] += 1

    # Generate summary
    valid_count = sum(1 for r in results["files"].values() if r["valid"])
    invalid_count = len(results["files"]) - valid_count

    results["summary"] = {
        "total": len(results["files"]),
        "valid": valid_count,
        "invalid": invalid_count,
        "manufacturers": len(results["by_manufacturer"])
    }

    logging.info(f"\n{'='*60}")
    logging.info("SUMMARY:")
    logging.info(f"  Total Files:     {results['summary']['total']}")
    logging.info(f"  Valid:           {results['summary']['valid']}")
    logging.info(f"  Invalid:         {results['summary']['invalid']}")
    if recursive:
        logging.info(f"  Manufacturers:   {results['summary']['manufacturers']}")
        logging.info("")
        logging.info("By Manufacturer:")
        for mfr, data in sorted(results["by_manufacturer"].items()):
            logging.info(
                f"  {mfr:30s} Total: {len(data['files']):3d}  Valid: {data['valid']:3d}  Invalid: {data['invalid']:3d}"
            )
    logging.info(f"{'='*60}")

    # Save to file if requested
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        logging.info(f"\nResults saved to: {output_file}")

    return results


def main() -> int:
    """Main entry point for validating KEK update file(s)."""
    parser = argparse.ArgumentParser(
        description="Validate KEK update file(s) - single file or folder"
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to a KEK update file (.bin) or folder containing KEK update files"
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Path to output JSON file (default: <path>_validation_results.json, always generated)"
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Process subdirectories recursively (only applicable for folders)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress validation output (show only summary)"
    )

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(message)s'
    )

    # Validate path exists
    if not args.path.exists():
        logging.error(f"Path not found: {args.path}")
        return 1

    # Determine if path is a file or directory
    if args.path.is_file():
        # Validate single file
        if not args.path.suffix == '.bin':
            logging.error(f"File must have .bin extension: {args.path}")
            return 1

        # Determine output file
        if args.output is None:
            output_file = args.path.parent / f"{args.path.stem}_validation_results.json"
        else:
            output_file = args.output

        # Validate the single file
        file_result = validate_single_kek(args.path, quiet=args.quiet)

        # Create results structure
        results = {
            "validation_date": datetime.now(timezone.utc).isoformat(),
            "file": str(args.path),
            "parameters": {
                "var_name": KEK_NAME,
                "var_guid": KEK_GUID,
                "attributes": KEK_ATTRIBUTES
            },
            "result": file_result
        }

        # Save to file
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        logging.info(f"Results saved to: {output_file}")

        # Return exit code based on validation
        return 0 if file_result["valid"] else 1

    elif args.path.is_dir():
        # Validate folder
        # Determine output file
        if args.output is None:
            output_file = args.path.parent / f"{args.path.name}_validation_results.json"
        else:
            output_file = args.output

        # Run validation
        results = validate_kek_folder(args.path, output_file, quiet=args.quiet, recursive=args.recursive)

        # Return exit code based on results
        if results["summary"]["invalid"] > 0:
            return 1

        return 0

    else:
        logging.error(f"Invalid path type: {args.path}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

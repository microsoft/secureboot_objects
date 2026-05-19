# @file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Parse changed secure boot update binaries into JSON receipts for PR review."""

import argparse
import json
import os
import pathlib
from typing import Any

from utility_functions import get_signed_payload_receipt, get_unsigned_payload_receipt


def _receipt_output_path(
    input_file: pathlib.Path, output_dir: pathlib.Path, repo_root: pathlib.Path
) -> pathlib.Path:
    """Build the JSON output path for an input binary."""
    relative_file = input_file
    try:
        relative_file = input_file.resolve().relative_to(repo_root.resolve())
    except ValueError:
        relative_file = pathlib.Path(input_file.name)

    return output_dir / relative_file.with_suffix(f"{relative_file.suffix}.json")


def parse_update_bin(input_file: pathlib.Path) -> tuple[dict[str, Any], str]:
    """Parse an update binary as signed auth var first, then as unsigned signature database."""
    try:
        return get_signed_payload_receipt(input_file), "signed"
    except Exception as signed_error:
        try:
            return get_unsigned_payload_receipt(input_file), "unsigned"
        except Exception as unsigned_error:
            raise ValueError(
                f"{input_file} is not a recognized signed or unsigned update payload "
                f"(signed error: {signed_error}; unsigned error: {unsigned_error})"
            ) from unsigned_error


def parse_files(
    files: list[pathlib.Path], output_dir: pathlib.Path, repo_root: pathlib.Path
) -> dict[str, list[dict[str, str]]]:
    """Parse each file and emit receipts under the output directory."""
    summary: dict[str, list[dict[str, str]]] = {"parsed": [], "skipped": []}
    output_dir.mkdir(parents=True, exist_ok=True)

    for file in files:
        if not file.is_file():
            summary["skipped"].append({"file": str(file), "reason": "File not found"})
            continue

        try:
            receipt, mode = parse_update_bin(file)
            output_file = _receipt_output_path(file, output_dir, repo_root)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(f"{json.dumps(receipt, indent=2)}\n", encoding="utf-8")
            summary["parsed"].append({"file": str(file), "mode": mode, "output": str(output_file)})
        except ValueError as error:
            summary["skipped"].append({"file": str(file), "reason": str(error)})

    return summary


def _print_summary(summary: dict[str, list[dict[str, str]]]) -> None:
    """Print and write a workflow summary of parsed files."""
    parsed_count = len(summary["parsed"])
    skipped_count = len(summary["skipped"])

    lines = [
        "## Parsed EFI Update Binaries",
        "",
        f"- Parsed: {parsed_count}",
        f"- Skipped: {skipped_count}",
        "",
    ]

    if summary["parsed"]:
        lines.append("### Parsed Files")
        for item in summary["parsed"]:
            lines.append(f"- `{item['file']}` ({item['mode']}) -> `{item['output']}`")
        lines.append("")

    if summary["skipped"]:
        lines.append("### Skipped Files")
        for item in summary["skipped"]:
            lines.append(f"- `{item['file']}`: {item['reason']}")
        lines.append("")

    output = "\n".join(lines)
    print(output)

    step_summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if step_summary_file:
        with open(step_summary_file, "a", encoding="utf-8") as summary_file:
            summary_file.write(f"{output}\n")


def _read_file_list(file_list: pathlib.Path) -> list[pathlib.Path]:
    """Read newline-separated file paths from a file."""
    return [pathlib.Path(line.strip()) for line in file_list.read_text(encoding="utf-8").splitlines() if line.strip()]


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Parse signed/unsigned secure boot update binaries into JSON receipts."
    )
    parser.add_argument("files", nargs="*", type=pathlib.Path, help="Binary files to parse.")
    parser.add_argument("--file-list", type=pathlib.Path, help="Path to a newline-separated list of binary files.")
    parser.add_argument(
        "--output-dir",
        type=pathlib.Path,
        required=True,
        help="Directory where receipt JSON files are written.",
    )
    parser.add_argument(
        "--repo-root",
        type=pathlib.Path,
        default=pathlib.Path("."),
        help="Repository root used for output paths.",
    )
    args = parser.parse_args()

    if not args.files and not args.file_list:
        parser.error("Provide at least one input file or --file-list.")

    return args


def main() -> int:
    """Entry point for parsing changed update binaries."""
    args = parse_args()
    files = list(args.files)
    if args.file_list:
        files.extend(_read_file_list(args.file_list))

    summary = parse_files(files, args.output_dir, args.repo_root)
    _print_summary(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

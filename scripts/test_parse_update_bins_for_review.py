# @file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Tests for parsing update binaries for PR review artifacts."""

import json
import pathlib

import parse_update_bins_for_review
from _pytest.monkeypatch import MonkeyPatch


def test_parse_files_prefers_signed_format(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    """It should parse signed payloads first and emit a JSON receipt file."""
    repo_root = tmp_path
    input_file = repo_root / "PostSignedObjects" / "KEK" / "x64" / "KEKUpdate.bin"
    input_file.parent.mkdir(parents=True, exist_ok=True)
    input_file.write_bytes(b"test")

    monkeypatch.setattr(
        parse_update_bins_for_review,
        "get_signed_payload_receipt",
        lambda _: {"fileName": "KEKUpdate.bin", "signatureDatabase": []},
    )
    monkeypatch.setattr(
        parse_update_bins_for_review,
        "get_unsigned_payload_receipt",
        lambda _: (_ for _ in ()).throw(AssertionError("unsigned parser should not be called")),
    )

    output_dir = tmp_path / "receipts"
    summary = parse_update_bins_for_review.parse_files([input_file], output_dir, repo_root)

    assert len(summary["parsed"]) == 1
    assert summary["parsed"][0]["mode"] == "signed"
    assert summary["skipped"] == []

    receipt_file = output_dir / "PostSignedObjects" / "KEK" / "x64" / "KEKUpdate.bin.json"
    assert receipt_file.exists()
    assert json.loads(receipt_file.read_text(encoding="utf-8"))["fileName"] == "KEKUpdate.bin"


def test_parse_files_falls_back_to_unsigned_format(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    """It should fall back to unsigned parsing if signed parsing fails."""
    repo_root = tmp_path
    input_file = repo_root / "PostSignedObjects" / "DB" / "x64" / "DBUpdate.bin"
    input_file.parent.mkdir(parents=True, exist_ok=True)
    input_file.write_bytes(b"test")

    monkeypatch.setattr(
        parse_update_bins_for_review,
        "get_signed_payload_receipt",
        lambda _: (_ for _ in ()).throw(ValueError("not signed")),
    )
    monkeypatch.setattr(
        parse_update_bins_for_review,
        "get_unsigned_payload_receipt",
        lambda _: {"fileName": "DBUpdate.bin", "signatureDatabase": []},
    )

    output_dir = tmp_path / "receipts"
    summary = parse_update_bins_for_review.parse_files([input_file], output_dir, repo_root)

    assert len(summary["parsed"]) == 1
    assert summary["parsed"][0]["mode"] == "unsigned"
    assert summary["skipped"] == []


def test_parse_files_marks_unrecognized_payloads_as_skipped(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    """It should skip files that are neither signed nor unsigned update payloads."""
    repo_root = tmp_path
    input_file = repo_root / "PostSignedObjects" / "Optional" / "other.bin"
    input_file.parent.mkdir(parents=True, exist_ok=True)
    input_file.write_bytes(b"test")

    monkeypatch.setattr(
        parse_update_bins_for_review,
        "get_signed_payload_receipt",
        lambda _: (_ for _ in ()).throw(ValueError("not signed")),
    )
    monkeypatch.setattr(
        parse_update_bins_for_review,
        "get_unsigned_payload_receipt",
        lambda _: (_ for _ in ()).throw(ValueError("not unsigned")),
    )

    output_dir = tmp_path / "receipts"
    summary = parse_update_bins_for_review.parse_files([input_file], output_dir, repo_root)

    assert summary["parsed"] == []
    assert len(summary["skipped"]) == 1
    assert "not a recognized signed or unsigned update payload" in summary["skipped"][0]["reason"]

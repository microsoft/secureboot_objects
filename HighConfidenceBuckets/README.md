# High Confidence Buckets

This directory contains a curated dataset of device firmware configurations
that have been identified with high confidence from Windows telemetry. These
records are used to inform Secure Boot policy decisions — specifically, to
determine which devices can safely receive certificate and revocation updates.
For background on the Secure Boot certificate renewal program, see
[aka.ms/getSecureBoot](https://aka.ms/getSecureBoot).

## Background

### What is a bucket?

A "bucket" is a set of SMBIOS field values that, taken together, uniquely
identify a specific device firmware configuration. Each bucket corresponds to
a distinct combination of OEM identity, board identity, and UEFI firmware
identity as reported by the device's System Management BIOS (SMBIOS) tables.
The bucket concept exists because Secure Boot policy decisions must be made
at the firmware level — the granularity of an individual firmware build on a
specific board — rather than at the OS or driver level.

### What makes a bucket "high confidence"?

Not all SMBIOS data is equally useful. Many devices ship with placeholder
strings (e.g., `"To Be Filled By O.E.M."`, `"Default string"`, `"Not
Applicable"`) that cannot distinguish one device from another. A high
confidence bucket is one where the SMBIOS fields carry real, specific values
that:

1. **Are non-trivial** — not placeholder or default strings.
2. **Are stable** — consistent across Windows telemetry observations of the
   same device model over time.
3. **Are discriminating** — the combination of field values uniquely identifies
   the firmware build, not just a broad product line.

Buckets that do not meet these criteria are excluded from this dataset because
acting on them could affect unintended devices.

### How were these buckets derived?

The records in this dataset are sourced from Windows diagnostic telemetry.
When a Windows device boots, SMBIOS table data is collected as part of
diagnostic data and uploaded. This telemetry provides a large-scale view of
what firmware configurations exist in the field.

The pipeline that produces this dataset:

1. Collects SMBIOS fields from telemetry across the Windows fleet.
2. Computes a SHA-256 hash over the normalized combination of identifying
   fields to produce a stable `BA_BucketId` for each distinct configuration.
3. Applies quality filters to retain only records whose field values are
   sufficiently specific and non-trivial.
4. Publishes the resulting set as this CSV dataset for use in Secure Boot
   policy analysis, update targeting, and device compatibility validation.

## File Format

The dataset is split across 16 part files to keep individual file sizes
manageable for Git:

```
HighConfidenceBuckets_part1.csv
HighConfidenceBuckets_part2.csv
...
HighConfidenceBuckets_part16.csv
```

Each file is a standard comma-separated values (CSV) with a header row.
The combined dataset contains approximately 1.5 million records. Records are
not sorted by any meaningful key; the split across files is purely mechanical.

### Columns

| Column | Description |
|---|---|
| `BA_BucketId` | **Boot Application Bucket ID.** A 64-character lowercase hexadecimal SHA-256 hash that uniquely identifies this firmware configuration. This is the primary key for the dataset. |
| `OSArchitecture` | The CPU architecture of the Windows installation that reported this record. Values: `AMD64`, `x86`, `arm64`. |
| `OEMName` | The OEM name string from SMBIOS Type 1 (System Information), field `Manufacturer`. |
| `OEMManufacturerName` | The system manufacturer string from SMBIOS Type 1. May duplicate `OEMName` or carry a more specific value depending on how the OEM populated their tables. |
| `BaseBoardManufacturer` | The baseboard manufacturer string from SMBIOS Type 2 (Base Board Information), field `Manufacturer`. |
| `OEMModelSystemFamily` | The system family string from SMBIOS Type 1, field `Family`. Identifies a product line (e.g., `ThinkPad`, `EliteBook`). |
| `OEMModelBaseBoard` | The baseboard product name from SMBIOS Type 2, field `Product`. |
| `OEMModelBaseBoardVersion` | The baseboard version string from SMBIOS Type 2, field `Version`. |
| `OEMModelSKU` | The system SKU number from SMBIOS Type 1, field `SKU Number`. Typically a full part number string. |
| `OEMModelNumber` | The system product name from SMBIOS Type 1, field `Product Name`. |
| `OEMModelSystemVersion` | The system version string from SMBIOS Type 1, field `Version`. |
| `FirmwareManufacturer` | The BIOS vendor string from SMBIOS Type 0 (BIOS Information), field `Vendor` (e.g., `American Megatrends Inc.`, `Insyde Corp`). |
| `FirmwareVersion` | The BIOS version string from SMBIOS Type 0, field `BIOS Version`. |
| `FirmwareReleaseDate` | The BIOS release date from SMBIOS Type 0, field `BIOS Release Date`. Format: `MM/DD/YYYY`. |

### BA_BucketId

The `BA_BucketId` is computed by hashing the normalized values of the
identifying SMBIOS fields. It serves as a stable, opaque reference to a
firmware configuration that can be used in policy systems without embedding
the raw SMBIOS strings. When the same combination of field values is observed
across many devices, they all share the same `BA_BucketId`.

### Data quality notes

Even within the high confidence dataset, some field values may contain strings
that indicate the OEM did not fully populate that particular SMBIOS field.
Common placeholder patterns include:

- `To Be Filled By O.E.M.`
- `Default string`
- `Not Defined`
- `Not Applicable`
- `INVALID`
- `x.x`

These values may appear in secondary fields (e.g., `OEMModelBaseBoardVersion`)
even when the primary identifying fields (e.g., `OEMModelSKU`,
`FirmwareVersion`) are specific. The high confidence classification applies to
the bucket as a whole — the combination of fields is still sufficiently
discriminating — not necessarily to every individual field in the record.

All string fields are unquoted unless the value itself contains a comma, in
which case standard CSV quoting applies. Empty fields appear as adjacent
commas with no value between them.

## Example record

```
BA_BucketId,OSArchitecture,OEMName,OEMManufacturerName,BaseBoardManufacturer,OEMModelSystemFamily,OEMModelBaseBoard,OEMModelBaseBoardVersion,OEMModelSKU,OEMModelNumber,OEMModelSystemVersion,FirmwareManufacturer,FirmwareVersion,FirmwareReleaseDate
0005a64cfa30ff6efa04319e93c408bc7a9c759a4a724ab25f890d7fac624784,AMD64,NEC,NEC,NEC,MATE,312E,Not Defined,PC-MKM21CZ6V424MRSSA,PC-MKM21CZG4,NEC Product,NEC,M1UKT50A,02/17/2020
```

## Related resources

- [aka.ms/getSecureBoot](https://aka.ms/getSecureBoot) — Microsoft guidance on
  the Secure Boot certificate renewal program.
- [secureboot_objects wiki](https://github.com/microsoft/secureboot_objects/wiki)
  — Documentation for the broader Secure Boot objects repository.
- `../PreSignedObjects/` — Unsigned Secure Boot payloads (DB, DBX, KEK, PK).
- `../PostSignedObjects/` — Microsoft-signed Secure Boot payloads for runtime use.

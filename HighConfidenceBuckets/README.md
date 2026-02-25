# High Confidence Buckets

This directory contains a curated dataset of device firmware and hardware configurations
that have been identified with high confidence from Windows telemetry to sucessfully apply the Secure Boot DB and KEK 2023 updates. These
records are used to inform Secure Boot policy decisions — specifically, to
determine which devices can safely receive and apply the certificate updates as part of the Latest Cumulative Updates (LCU).
For background on the Secure Boot certificate renewal program, see
[aka.ms/getSecureBoot](https://aka.ms/getSecureBoot).

## Background

### What is a bucket?

A "bucket" is a set of System Management BIOS (SMBIOS) field values that, taken together, uniquely
identify a specific device firmware and hardware configuration. Each bucket corresponds to
a distinct combination of the OEM identity, board identity, and UEFI firmware
identity as reported by the device's SMBIOS tables.

### What makes a bucket "high confidence"?

Microsoft relies on Windows Required Diagnostic Data to inform whether Secure Boot key updates are successfully applied, or whether the firmware and/or hardware, rejects the updates. When a statistically significant decision has been reached, the bucket is allow listed in this list and the LCU, and delivered to systems via Windows servicing. 

### How were these buckets derived?

Microsoft partnered with device manufacturers to understand the set of attributes that define a bucket. The records in this dataset are sourced from Windows diagnostic data. When a Windows device boots, SMBIOS table data is collected as part of diagnostic data. This data provides a large-scale view of what firmware and hardware configurations exist in the ecosystem. 

The pipeline that produces this dataset:

1. Collects SMBIOS fields from data across the Windows ecosystem.
2. Computes a SHA-256 hash over the bucket attributes fields to produce a unique `BA_BucketId` for each distinct device configuration.
3. Applies filters to retain only records where statistical significance has been shown.
4. Publishes the resulting set as part of this CSV dataset for use in Secure Boot policy analysis, update targeting, and device compatibility validation.

## File Format

The dataset is split across 16 part files to keep individual file sizes manageable for Git:

```
HighConfidenceBuckets_part1.csv
HighConfidenceBuckets_part2.csv
...
HighConfidenceBuckets_part16.csv
```

Each file is a comma-separated values (CSV) file with a header row. The combined dataset contains millions of records. Records are not sorted by any meaningful key; the split across files is purely mechanical.

### Columns

| Column | Description |
|---|---|
| `BA_BucketId` | **Bucket ID** A 64-character lowercase hexadecimal SHA-256 hash that uniquely identifies this firmware and hardware configuration. This is the primary key for the dataset. |
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

### Data quality notes

Even within the high confidence dataset, some field values may contain strings that indicate the OEM did not fully populate that particular SMBIOS field. Common placeholder patterns include:

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
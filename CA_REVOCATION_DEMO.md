# Real-World CA Revocation Space Savings Demonstration

This document demonstrates the space savings achieved by using the CA revocation feature with real Microsoft DBX data.

## Test Setup

Using the existing Microsoft DBX database (`dbx_info_msft_06_10_25.json`) which contains:
- **Total entries**: 430 hashes across all architectures
- **Microsoft Corporation UEFI CA 2011 signed**: 228 hashes (53%)
- **Microsoft Windows Production PCA 2011 signed**: 173 hashes (40%)
- **Combined Microsoft CAs**: 401 hashes (93%)

## Results (X64 Architecture)

### Baseline (No CA Revocation)
- **DBX Size**: 22,211 bytes
- **Description**: Full DBX with all hashes and both CA certificates

### Single CA Revocation (Windows Production PCA 2011)
- **DBX Size**: 13,907 bytes
- **Space Savings**: 8,304 bytes (37.4% reduction)
- **Hashes Removed**: 173 entries
- **Command**: 
  ```bash
  python3 scripts/secure_boot_default_keys.py --keystore Templates/RealWorldCARevocationDemo.toml -o output/ --exclude-revoked-ca-hashes
  ```

### Dual CA Revocation (Both Microsoft CAs)
- **DBX Size**: 4,563 bytes
- **Space Savings**: 17,648 bytes (79.5% reduction)
- **Hashes Removed**: 401 entries (93% of all hashes)
- **Command**: Same as above, but with both CAs in the template

## Template File

The demonstration uses `Templates/RealWorldCARevocationDemo.toml` which includes:

1. **Revoked CAs in DBX**:
   - Microsoft Corporation UEFI CA 2011
   - Microsoft Windows Production PCA 2011

2. **DBX Hash List**: The real Microsoft DBX data file

3. **Minimal Setup**: Basic PK, KEK, and DB certificates for functionality

## Key Benefits Demonstrated

1. **Massive Space Savings**: Up to 79.5% reduction in DBX size
2. **Real-World Applicability**: Uses actual Microsoft DBX production data
3. **Granular Control**: Can revoke individual CAs or combinations
4. **Clear Logging**: Shows exactly what hashes are being removed and why

## Use Cases

This feature is particularly valuable for:
- Firmware with limited storage space for secure boot variables
- Environments where specific CAs have been compromised
- Organizations wanting to minimize attack surface by removing unnecessary trust relationships
- Compliance scenarios requiring specific CA exclusions

## Override Capabilities

The new `allow_hashes_by_ca` field provides fine-grained control:
- Specify CA names (not individual hashes) to preserve
- More intuitive than managing individual hash lists
- Flexible matching against signing authority fields
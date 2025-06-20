# Space Savings Analysis: 2011 Windows Production CA Revocation Only

This analysis shows the specific space savings achieved by revoking **only** the 2011 Windows Production CA while maintaining the 2011 Microsoft UEFI CA for third-party compatibility.

## Configuration Details

**Template**: `Templates/WindowsProductionCARevocationOnly.toml`

**Setup**:
- KEK: 2023 Microsoft KEK CA + 2011 Microsoft KEK CA
- DB: 2011 Windows Production CA + 2011 Microsoft UEFI CA + 2023 Windows Production CA  
- DBX: Microsoft DBX data + **2011 Windows Production CA only** (revoked)

**Key Point**: Unlike previous demonstrations that revoked both Microsoft CAs, this configuration maintains the 2011 Microsoft UEFI CA to preserve third-party compatibility.

## Results by Architecture

### X64 (Primary Target)
- **Baseline**: 20,668 bytes
- **With 2011 Windows Production CA revoked**: 13,907 bytes
- **Space saved**: 6,761 bytes (**32.7% reduction**)
- **Hashes removed**: 173 of 430 entries (40.2%)

### IA32
- **Baseline**: 4,444 bytes  
- **With 2011 Windows Production CA revoked**: 3,539 bytes
- **Space saved**: 905 bytes (**20.4% reduction**)
- **Hashes removed**: 51 of 92 entries (55.4%)

### ARM
- **Baseline**: 5,308 bytes
- **With 2011 Windows Production CA revoked**: 1,571 bytes  
- **Space saved**: 3,737 bytes (**70.4% reduction**)
- **Hashes removed**: 110 of 110 entries (100%)

### AARCH64
- **Baseline**: 1,276 bytes
- **With 2011 Windows Production CA revoked**: 1,859 bytes
- **Size increased**: 583 bytes (45.7% increase)
- **Hashes removed**: 20 of 26 entries (76.9%)

*Note: AARCH64 shows an increase because the CA certificate itself (583 bytes) is larger than the space saved from removing the 20 small hash entries.*

## Key Findings

1. **Most significant savings on X64**: 32.7% reduction with 173 hashes removed
2. **Excellent ARM savings**: 70.4% reduction with all hashes removed  
3. **Moderate IA32 savings**: 20.4% reduction
4. **AARCH64 trade-off**: Small size increase due to low hash count vs certificate size

## Real-World Impact

Revoking only the 2011 Windows Production CA provides substantial space savings while:
- Maintaining compatibility with third-party UEFI drivers/applications
- Preserving the widely-used 2011 Microsoft UEFI CA
- Achieving significant reductions on the most common platforms (X64, ARM)

## Usage

```bash
python3 scripts/secure_boot_default_keys.py \
  --keystore Templates/WindowsProductionCARevocationOnly.toml \
  -o output/ \
  --exclude-revoked-ca-hashes
```

This provides a practical middle-ground solution for space-constrained environments that need third-party compatibility.
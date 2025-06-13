# PowerShell Script Validation Tests

This directory contains test scripts to validate PowerShell scripts in the repository.

## test_Make2023BootableMedia_spelling.ps1

This test script validates the spelling corrections made to `Make2023BootableMedia.ps1` as part of issue #220.

### Purpose

The script performs comprehensive automated static analysis tests to ensure that spelling corrections introduce no adverse effects to the PowerShell script functionality.

### Test Categories

1. **PowerShell Syntax Validation** - Ensures the script parses correctly
2. **Variable Consistency Checks** - Verifies all `ISO_Label` variables use consistent spelling
3. **Function Definition Integrity** - Confirms all key functions are present
4. **Parameter Block Validation** - Validates parameter definitions
5. **Critical Variable Usage** - Checks that critical variables are used correctly
6. **Spelling Correction Verification** - Confirms specific spelling fixes
7. **Script Loading Tests** - Verifies the script can be loaded without errors

### Usage

```powershell
# Run from the scripts directory
cd scripts
pwsh -File test_Make2023BootableMedia_spelling.ps1

# Or specify a custom path to the script being tested
pwsh -File test_Make2023BootableMedia_spelling.ps1 -ScriptPath "path\to\Make2023BootableMedia.ps1"
```

### Expected Results

When all tests pass, you should see:
- ✅ 15 tests passed
- ❌ 0 tests failed
- 🎉 Success message confirming no adverse effects

### What the Tests Validate

The tests specifically validate the following fixes from issue #220:

- **Variable Name Consistency**: Ensures all instances of `$global:ISO_Lable` have been corrected to `$global:ISO_Label`
- **Spelling Corrections**: Verifies "Avalable" → "Available", "defualt" → "default" 
- **Comment Corrections**: Confirms comment spelling has been fixed
- **Functional Integrity**: Ensures the corrections don't break script functionality

### Requirements

- PowerShell 5.1 or later (PowerShell Core recommended)
- The `Make2023BootableMedia.ps1` script must be present in the expected location

### Exit Codes

- `0`: All tests passed
- `1`: One or more tests failed
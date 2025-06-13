#Requires -Version 5.1

<#
.SYNOPSIS
    Test script to validate spelling corrections in Make2023BootableMedia.ps1

.DESCRIPTION
    This script performs automated static analysis tests to ensure that the spelling
    corrections made to Make2023BootableMedia.ps1 introduce no adverse effects.
    
    Tests include:
    - PowerShell syntax validation
    - Variable consistency checks (ISO_Label vs ISO_Lable)
    - Function definition integrity
    - Parameter block validation
    - Critical variable usage validation
    - Spelling correction verification
    - Script loading tests

.NOTES
    Created to validate fixes for issue #220 - "Lable" misspelling
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ScriptPath = "$PSScriptRoot\windows\Make2023BootableMedia.ps1"
)

# Test results tracking
$script:TestResults = @()
$script:TestsPassed = 0
$script:TestsFailed = 0

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = ""
    )
    
    $result = [PSCustomObject]@{
        TestName = $TestName
        Passed = $Passed
        Details = $Details
        Timestamp = Get-Date
    }
    
    $script:TestResults += $result
    
    if ($Passed) {
        $script:TestsPassed++
        Write-Host "✅ PASS: $TestName" -ForegroundColor Green
        if ($Details) {
            Write-Host "   $Details" -ForegroundColor Gray
        }
    } else {
        $script:TestsFailed++
        Write-Host "❌ FAIL: $TestName" -ForegroundColor Red
        if ($Details) {
            Write-Host "   $Details" -ForegroundColor Yellow
        }
    }
}

function Test-PowerShellSyntax {
    Write-Host "`n🔍 Testing PowerShell syntax validation..." -ForegroundColor Cyan
    
    try {
        $scriptContent = Get-Content -Path $ScriptPath -Raw
        $tokens = $null
        $errors = $null
        
        # Parse the PowerShell script
        [System.Management.Automation.Language.Parser]::ParseInput(
            $scriptContent, 
            [ref]$tokens, 
            [ref]$errors
        ) | Out-Null
        
        if ($errors.Count -eq 0) {
            Write-TestResult "PowerShell Syntax Validation" $true "Script parses without syntax errors"
        } else {
            $errorDetails = ($errors | ForEach-Object { "$($_.Message) at line $($_.Extent.StartLineNumber)" }) -join "; "
            Write-TestResult "PowerShell Syntax Validation" $false "Syntax errors found: $errorDetails"
        }
    } catch {
        Write-TestResult "PowerShell Syntax Validation" $false "Exception during parsing: $($_.Exception.Message)"
    }
}

function Test-VariableConsistency {
    Write-Host "`n🔍 Testing variable consistency..." -ForegroundColor Cyan
    
    $scriptContent = Get-Content -Path $ScriptPath -Raw
    
    # Check for the old misspelled variable name
    $oldVariableMatches = [regex]::Matches($scriptContent, '\$global:ISO_Lable', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    
    if ($oldVariableMatches.Count -eq 0) {
        Write-TestResult "Variable Consistency - No ISO_Lable" $true "No instances of misspelled 'ISO_Lable' found"
    } else {
        Write-TestResult "Variable Consistency - No ISO_Lable" $false "Found $($oldVariableMatches.Count) instances of misspelled 'ISO_Lable'"
    }
    
    # Check for the correct variable name
    $newVariableMatches = [regex]::Matches($scriptContent, '\$global:ISO_Label', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    
    if ($newVariableMatches.Count -ge 4) {
        Write-TestResult "Variable Consistency - ISO_Label Present" $true "Found $($newVariableMatches.Count) instances of correctly spelled 'ISO_Label'"
    } else {
        Write-TestResult "Variable Consistency - ISO_Label Present" $false "Expected at least 4 instances of 'ISO_Label', found $($newVariableMatches.Count)"
    }
    
    # Check for other misspellings that were fixed
    $availableCheck = $scriptContent -notmatch "Avalable"
    Write-TestResult "Spelling - Available" $availableCheck "Verified 'Avalable' has been corrected to 'Available'"
    
    $defaultCheck = $scriptContent -notmatch "defualt"
    Write-TestResult "Spelling - Default" $defaultCheck "Verified 'defualt' has been corrected to 'default'"
}

function Test-FunctionDefinitionIntegrity {
    Write-Host "`n🔍 Testing function definition integrity..." -ForegroundColor Cyan
    
    try {
        $scriptContent = Get-Content -Path $ScriptPath -Raw
        
        # Extract function definitions using regex
        $functionMatches = [regex]::Matches($scriptContent, 'function\s+([A-Za-z-_]+)\s*\{', [System.Text.RegularExpressions.RegexOptions]::Multiline)
        
        # Core functions that should be present (not exhaustive, just key ones)
        $expectedFunctions = @(
            'Get-TS',
            'Show-Usage',
            'Show-ADK-Req',
            'Write-Dbg-Host',
            'Initialize-MediaPaths',
            'Create-USBMedia',
            'Create-ISOMedia'
        )
        
        $foundFunctions = $functionMatches | ForEach-Object { $_.Groups[1].Value }
        $missingFunctions = $expectedFunctions | Where-Object { $_ -notin $foundFunctions }
        
        if ($missingFunctions.Count -eq 0) {
            Write-TestResult "Function Definition Integrity" $true "All key functions found (tested $($expectedFunctions.Count) core functions)"
        } else {
            Write-TestResult "Function Definition Integrity" $false "Missing functions: $($missingFunctions -join ', ')"
        }
        
        # Check that we found a reasonable number of functions (should be at least 10)
        if ($foundFunctions.Count -ge 10) {
            Write-TestResult "Function Count" $true "Found $($foundFunctions.Count) function definitions"
        } else {
            Write-TestResult "Function Count" $false "Only found $($foundFunctions.Count) function definitions, expected at least 10"
        }
        
    } catch {
        Write-TestResult "Function Definition Integrity" $false "Exception during function analysis: $($_.Exception.Message)"
    }
}

function Test-ParameterBlockValidation {
    Write-Host "`n🔍 Testing parameter block validation..." -ForegroundColor Cyan
    
    try {
        $scriptContent = Get-Content -Path $ScriptPath -Raw
        
        # Check for param block at the beginning
        $paramBlockFound = $scriptContent -match '(?s)param\s*\([^)]+\)'
        
        if ($paramBlockFound) {
            Write-TestResult "Parameter Block Present" $true "Parameter block found in script"
        } else {
            Write-TestResult "Parameter Block Present" $false "Parameter block not found"
        }
        
        # Check for expected parameters
        $expectedParams = @('MediaPath', 'TargetType', 'ISOPath', 'USBDrive', 'FileSystem', 'NewMediaPath', 'StagingDir')
        $missingParams = @()
        
        foreach ($param in $expectedParams) {
            if ($scriptContent -notmatch "\[\s*Parameter[^]]*\]\s*\[\s*string\s*\]\s*\`$$param") {
                $missingParams += $param
            }
        }
        
        if ($missingParams.Count -eq 0) {
            Write-TestResult "Parameter Definitions" $true "All expected parameters found"
        } else {
            Write-TestResult "Parameter Definitions" $false "Missing parameters: $($missingParams -join ', ')"
        }
        
    } catch {
        Write-TestResult "Parameter Block Validation" $false "Exception during parameter validation: $($_.Exception.Message)"
    }
}

function Test-ScriptLoading {
    Write-Host "`n🔍 Testing script loading..." -ForegroundColor Cyan
    
    try {
        # Test that the script can be dot-sourced without errors
        # We'll do this in a separate PowerShell process to avoid affecting current session
        $testScript = @"
try {
    . '$ScriptPath'
    Write-Output "SUCCESS"
} catch {
    Write-Output "ERROR: `$(`$_.Exception.Message)"
}
"@
        
        $result = pwsh -Command $testScript
        
        if ($result -eq "SUCCESS") {
            Write-TestResult "Script Loading" $true "Script can be dot-sourced without errors"
        } else {
            Write-TestResult "Script Loading" $false "Script loading failed: $result"
        }
        
    } catch {
        Write-TestResult "Script Loading" $false "Exception during script loading test: $($_.Exception.Message)"
    }
}

function Test-CriticalVariableUsage {
    Write-Host "`n🔍 Testing critical variable usage..." -ForegroundColor Cyan
    
    $scriptContent = Get-Content -Path $ScriptPath -Raw
    
    # Check that ISO_Label is used in the oscdimg command line
    $oscdimgLineFound = $scriptContent -match "runCommand.*-l\`$global:ISO_Label"
    
    if ($oscdimgLineFound) {
        Write-TestResult "Critical Variable Usage - oscdimg" $true "ISO_Label variable correctly used in oscdimg command"
    } else {
        Write-TestResult "Critical Variable Usage - oscdimg" $false "ISO_Label variable not found in oscdimg command line"
    }
    
    # Check that ISO_Label is set from the volume label
    $volumeLabelAssignment = $scriptContent -match "\`$global:ISO_Label = \(Get-Volume"
    
    if ($volumeLabelAssignment) {
        Write-TestResult "Critical Variable Usage - Assignment" $true "ISO_Label variable correctly assigned from volume label"
    } else {
        Write-TestResult "Critical Variable Usage - Assignment" $false "ISO_Label assignment from volume label not found"
    }
}

function Test-SpecificSpellingCorrections {
    Write-Host "`n🔍 Testing specific spelling corrections..." -ForegroundColor Cyan
    
    $scriptContent = Get-Content -Path $ScriptPath -Raw
    
    # Test for specific line fixes mentioned in the issue
    $corrections = @{
        "Available (not Avalable)" = "Available.*http://aka.ms/adk"
        "default (not defualt)" = "# If.*ISOLabel.*not set.*then default"
        "ISOLabel (not ISOLable) in comment" = "# If.*ISOLabel.*not set"
    }
    
    foreach ($correctionName in $corrections.Keys) {
        $pattern = $corrections[$correctionName]
        $found = $scriptContent -match $pattern
        
        Write-TestResult "Spelling Correction - $correctionName" $found "Verified spelling correction is present"
    }
}

# Main test execution
function Run-AllTests {
    Write-Host "🧪 Starting validation tests for Make2023BootableMedia.ps1 spelling corrections" -ForegroundColor Magenta
    Write-Host "Script path: $ScriptPath" -ForegroundColor Gray
    
    if (-not (Test-Path $ScriptPath)) {
        Write-Host "❌ ERROR: Script not found at $ScriptPath" -ForegroundColor Red
        return
    }
    
    # Run all tests
    Test-PowerShellSyntax
    Test-VariableConsistency
    Test-FunctionDefinitionIntegrity
    Test-ParameterBlockValidation
    Test-CriticalVariableUsage
    Test-SpecificSpellingCorrections
    Test-ScriptLoading
    
    # Summary
    Write-Host "`n📊 Test Summary:" -ForegroundColor Magenta
    Write-Host "✅ Passed: $script:TestsPassed" -ForegroundColor Green
    Write-Host "❌ Failed: $script:TestsFailed" -ForegroundColor Red
    Write-Host "📋 Total:  $($script:TestsPassed + $script:TestsFailed)" -ForegroundColor Cyan
    
    if ($script:TestsFailed -eq 0) {
        Write-Host "`n🎉 All tests passed! The spelling corrections introduce no adverse effects." -ForegroundColor Green
        return 0
    } else {
        Write-Host "`n⚠️  Some tests failed. Please review the results above." -ForegroundColor Yellow
        return 1
    }
}

# Execute tests if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    $exitCode = Run-AllTests
    exit $exitCode
}
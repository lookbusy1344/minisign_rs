<#
.SYNOPSIS
    Utility script to discover and clean up minisign credential entries from Windows Credential Manager.

.DESCRIPTION
    This script helps manage password entries saved by minisign_rs --save-password.
    It can list all minisign credential entries and delete selected ones.

    Requirements:
        - Windows (uses Credential Manager via advapi32.dll)
        - PowerShell 5.1 or later

.PARAMETER All
    Delete all minisign entries without prompting

.PARAMETER DryRun
    Show what would be deleted without actually deleting

.EXAMPLE
    .\cleanup_credentials.ps1
    # Interactive mode - list and selectively delete entries

.EXAMPLE
    .\cleanup_credentials.ps1 -All
    # Delete all entries (useful for cleanup after testing)

.EXAMPLE
    .\cleanup_credentials.ps1 -DryRun
    # Preview what would be deleted without actually deleting

.EXAMPLE
    .\cleanup_credentials.ps1 -All -DryRun
    # Preview deleting all entries
#>

[CmdletBinding()]
param(
    [switch]$All,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region P/Invoke Declarations

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CredentialManager
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    public static class AdvApi32
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredEnumerate(
            string Filter,
            int Flags,
            out int Count,
            out IntPtr Credentials);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CredDelete(
            string TargetName,
            int Type,
            int Flags);

        [DllImport("advapi32.dll")]
        public static extern void CredFree(IntPtr Buffer);
    }
}
"@

#endregion

#region Helper Functions

class CredentialEntry {
    [string]$CredentialId
    [string]$TargetName

    CredentialEntry([string]$credentialId, [string]$targetName) {
        $this.CredentialId = $credentialId
        $this.TargetName = $targetName
    }

    [string] ToString() {
        return $this.CredentialId
    }
}

function Find-MinisignEntries {
    <#
    .SYNOPSIS
        Find all minisign credential entries in Windows Credential Manager
    #>
    [CmdletBinding()]
    [OutputType([CredentialEntry[]])]
    param()

    $count = 0
    $credPtr = [IntPtr]::Zero
    [System.Collections.ArrayList]$entries = @()

    try {
        # Enumerate credentials using LegacyGeneric filter
        # Note: Using null filter can fail silently on some systems, so we use a specific filter
        $result = [CredentialManager.AdvApi32]::CredEnumerate("LegacyGeneric:target=*", 0, [ref]$count, [ref]$credPtr)

        if (-not $result) {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($lastError -eq 1168) {
                # ERROR_NOT_FOUND - no credentials exist, return empty array
                return [CredentialEntry[]]@()
            }
            throw "Failed to enumerate credentials. Error code: $lastError"
        }

        Write-Verbose "Found $count total LegacyGeneric credentials"

        for ($i = 0; $i -lt $count; $i++) {
            $credentialPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($credPtr, [IntPtr]::Size * $i)
            $credential = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                $credentialPtr,
                [type][CredentialManager.CREDENTIAL]
            )

            $targetName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($credential.TargetName)
            $userName = if ($credential.UserName -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::PtrToStringUni($credential.UserName)
            } else {
                ""
            }

            # Only process Generic credentials (Type = 1)
            if ($credential.Type -ne 1) {
                continue
            }

            # Filter for minisign credentials
            # The keyring crate on Windows uses LegacyGeneric format:
            # Target: "LegacyGeneric:target={credential_id}.minisign"
            # UserName: "{credential_id}"
            $credentialId = $null

            if ($targetName -match '^LegacyGeneric:target=([^.]+)\.minisign$') {
                # Windows LegacyGeneric format (keyring crate default on Windows)
                $credentialId = $Matches[1]
            }
            elseif ($targetName -match '^minisign:(.+)$') {
                # Format: "minisign:credential_id"
                $credentialId = $Matches[1]
            }
            elseif ($targetName -match '^minisign/(.+)$') {
                # Format: "minisign/credential_id"
                $credentialId = $Matches[1]
            }
            elseif ($targetName -eq 'minisign' -and $userName) {
                # Format: target="minisign", username=credential_id
                $credentialId = $userName
            }

            if ($credentialId) {
                Write-Verbose "Found minisign credential: $credentialId"
                [void]$entries.Add([CredentialEntry]::new($credentialId, $targetName))
            }
        }

        return [CredentialEntry[]]$entries.ToArray()
    }
    finally {
        # Always free the credential buffer
        if ($credPtr -ne [IntPtr]::Zero) {
            [CredentialManager.AdvApi32]::CredFree($credPtr)
        }
    }
}

function Select-Entries {
    <#
    .SYNOPSIS
        Select which entries to delete
    #>
    [CmdletBinding()]
    [OutputType([CredentialEntry[]])]
    param(
        [Parameter(Mandatory)]
        [CredentialEntry[]]$Entries,

        [Parameter(Mandatory)]
        [bool]$SelectAll
    )

    if ($SelectAll) {
        return $Entries
    }

    # Interactive selection
    Write-Host ""
    Write-Host "Enter selection (numbers separated by spaces, ranges like 1-3, 'all', 'q' or empty to quit)"

    $maxRetries = 3
    for ($attempt = 0; $attempt -lt $maxRetries; $attempt++) {
        try {
            $userInput = Read-Host "Selection"
            $userInput = $userInput.Trim()

            if ([string]::IsNullOrEmpty($userInput) -or $userInput -eq 'q') {
                return @()
            }

            if ($userInput -eq 'all') {
                return $Entries
            }

            # Parse selection
            $selectedIndices = @{}
            $parts = $userInput -split '\s+'

            foreach ($part in $parts) {
                if ($part -match '^(\d+)-(\d+)$') {
                    # Range like "1-3"
                    $start = [int]$Matches[1]
                    $end = [int]$Matches[2]

                    if ($start -lt 1 -or $end -gt $Entries.Count -or $start -gt $end) {
                        throw "Invalid range: $part"
                    }

                    for ($i = $start; $i -le $end; $i++) {
                        $selectedIndices[$i] = $true
                    }
                }
                elseif ($part -match '^\d+$') {
                    # Single number
                    $num = [int]$part
                    if ($num -lt 1 -or $num -gt $Entries.Count) {
                        throw "Number out of range: $num"
                    }
                    $selectedIndices[$num] = $true
                }
                else {
                    throw "Invalid input: $part"
                }
            }

            # Convert indices to entries (indices are 1-based)
            [System.Collections.ArrayList]$selected = @()
            foreach ($index in ($selectedIndices.Keys | Sort-Object)) {
                [void]$selected.Add($Entries[$index - 1])
            }

            return [CredentialEntry[]]$selected.ToArray()
        }
        catch {
            Write-Host "Invalid input: $_" -ForegroundColor Red
            if ($attempt -lt ($maxRetries - 1)) {
                Write-Host "Please try again ($($maxRetries - $attempt - 1) attempts remaining)"
            }
            else {
                Write-Host "Too many invalid attempts. Exiting."
                return @()
            }
        }
    }

    return @()
}

function Remove-CredentialEntry {
    <#
    .SYNOPSIS
        Delete a single credential entry from Windows Credential Manager
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [CredentialEntry]$Entry,

        [Parameter(Mandatory)]
        [ref]$ErrorMessage
    )

    try {
        $result = [CredentialManager.AdvApi32]::CredDelete($Entry.TargetName, 1, 0)

        if (-not $result) {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $ErrorMessage.Value = "Error code: $lastError"
            return $false
        }

        return $true
    }
    catch {
        $ErrorMessage.Value = $_.Exception.Message
        return $false
    }
}

#endregion

#region Main Logic

try {
    # Discovery phase
    Write-Host "Searching Windows Credential Manager for minisign entries..."

    $entries = @(Find-MinisignEntries)

    if ($entries.Count -eq 0) {
        Write-Host "No minisign entries found in Credential Manager"
        exit 0
    }

    Write-Host ""
    Write-Host "Found $($entries.Count) minisign credential entries:"
    for ($i = 0; $i -lt $entries.Count; $i++) {
        Write-Host "  $($i + 1). $($entries[$i])"
    }

    # Selection phase
    $selected = @(Select-Entries -Entries $entries -SelectAll $All)

    if ($selected.Count -eq 0) {
        Write-Host "No entries selected. Exiting."
        exit 0
    }

    Write-Host ""
    Write-Host "Selected $($selected.Count) entries for deletion:"
    foreach ($entry in $selected) {
        Write-Host "  - $entry"
    }

    if ($DryRun) {
        Write-Host ""
        Write-Host "Dry run mode - nothing was deleted"
        exit 0
    }

    # Deletion phase
    Write-Host ""
    Write-Host "Deleting entries..."
    $successes = @()
    $failures = @()

    foreach ($entry in $selected) {
        $errorMsg = ""
        $success = Remove-CredentialEntry -Entry $entry -ErrorMessage ([ref]$errorMsg)

        if ($success) {
            $successes += $entry
            Write-Host "  ✓ Deleted $($entry.CredentialId)" -ForegroundColor Green
        }
        else {
            $failures += @{Entry = $entry; Error = $errorMsg}
            Write-Host "  ✗ Failed to delete $($entry.CredentialId): $errorMsg" -ForegroundColor Red
        }
    }

    # Summary
    Write-Host ""
    Write-Host ("=" * 60)
    Write-Host "Deleted $($successes.Count) entries successfully"

    if ($failures.Count -gt 0) {
        $entryWord = if ($failures.Count -eq 1) { "entry" } else { "entries" }
        Write-Host "Failed to delete $($failures.Count) ${entryWord}:"
        foreach ($failure in $failures) {
            Write-Host "  - $($failure.Entry.CredentialId): $($failure.Error)"
        }
        exit 1
    }
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}

#endregion

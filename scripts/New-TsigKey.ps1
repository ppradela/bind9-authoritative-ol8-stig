<#
.SYNOPSIS
    Generate a BIND TSIG key stanza (hmac-sha384 by default) for inclusion in
    /etc/named/keys/tsig.key on a primary and every secondary that shares the
    same trust relationship.

.DESCRIPTION
    Uses .NET RandomNumberGenerator (cryptographically secure) to produce the
    shared secret, then prints a BIND named.conf 'key { ... };' stanza.
    Optionally writes the same stanza to a file with mode 0600 (POSIX) or
    a restrictive ACL (Windows).

.PARAMETER Name
    Key name as referenced from named.conf. Default: zone-transfer-key.

.PARAMETER Algorithm
    One of hmac-sha256, hmac-sha384, hmac-sha512. Default: hmac-sha384.

.PARAMETER Bits
    Secret length in bits. Multiple of 8, minimum 128. Default: 384.

.PARAMETER OutFile
    Optional path to also write the stanza to (mode 0600 / restrictive ACL).

.EXAMPLE
    .\New-TsigKey.ps1
    .\New-TsigKey.ps1 -Name zone-transfer-key -Algorithm hmac-sha384 -OutFile tsig.key
#>

[CmdletBinding()]
param(
    [string]$Name = "zone-transfer-key",

    [ValidateSet("hmac-sha256", "hmac-sha384", "hmac-sha512")]
    [string]$Algorithm = "hmac-sha384",

    [int]$Bits = 384,

    [string]$OutFile
)

if ($Bits -lt 128 -or ($Bits % 8) -ne 0) {
    Write-Error "Bits must be a multiple of 8 and at least 128."
    exit 2
}

$bytes = New-Object byte[] ($Bits / 8)
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try   { $rng.GetBytes($bytes) }
finally { $rng.Dispose() }

$secret = [Convert]::ToBase64String($bytes)

$stanza = @"
key "$Name" {
    algorithm $Algorithm;
    secret "$secret";
};
"@

Write-Output $stanza

if ($PSBoundParameters.ContainsKey('OutFile') -and $OutFile) {
    Set-Content -Path $OutFile -Value $stanza -NoNewline -Encoding ascii

    if ($IsLinux -or $IsMacOS) {
        # POSIX-style 0600
        & chmod 600 $OutFile | Out-Null
    } else {
        # Windows — restrict to the current user only
        $acl = Get-Acl -Path $OutFile
        $acl.SetAccessRuleProtection($true, $false)   # disable inheritance
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
            "FullControl", "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl -Path $OutFile -AclObject $acl
    }

    Write-Information ""  -InformationAction Continue
    Write-Information "Wrote key stanza to: $OutFile" -InformationAction Continue
    Write-Information "Install on primary AND every secondary that shares this trust:" -InformationAction Continue
    Write-Information "  install -d -o root -g named -m 0750 /etc/named/keys" -InformationAction Continue
    Write-Information "  install -o root -g named -m 0640 $OutFile /etc/named/keys/tsig.key" -InformationAction Continue
}

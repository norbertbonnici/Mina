<#
.SYNOPSIS
    Creates a self-signed code-signing certificate for signing LAB builds of the Mina endpoint
    package. A stand-in for PHASE0_DECISIONS assumption A6, not a replacement for it.

.DESCRIPTION
    CLAUDE.md requires endpoint code and scripts to be signed. The organisation does not yet hold a
    code-signing certificate -- A6 is still open, and procuring one is not an engineering task.
    Rather than leave the signing path untested until a real certificate turns up, the packaging
    pipeline takes a certificate thumbprint as a parameter and this script produces one that works
    in the lab. Swapping in the real certificate later is then a change of thumbprint, not a change
    of code, and the mechanism will already have been exercised end to end.

    What this certificate is NOT: trusted by anything by default. Windows validates Authenticode
    against the machine's trust stores, so a self-signed signature is a signature Windows can read
    and refuse. To make it validate on a lab endpoint, the exported .cer must be placed in that
    machine's Trusted Root Certification Authorities *and* Trusted Publishers stores -- which is a
    real trust change to that machine and should only ever be done to a lab client.

    Deliberately absent: any option to export the private key. Keeping it non-exportable in the
    creating user's store is the difference between a lab convenience and a signing key somebody
    can copy onto a build agent and forget about. If a lab CI job ever needs to sign, create a
    separate certificate there rather than moving this one.

.PARAMETER Subject
    Certificate subject. Defaults to a name that cannot be mistaken for a production identity.

.PARAMETER ValidYears
    Lifetime in years. Short by default -- a lab certificate that outlives the lab is how a
    stand-in quietly becomes production.

.PARAMETER ExportCerPath
    Where to write the public certificate for deployment to a lab endpoint's trust stores.

.EXAMPLE
    .\New-MinaLabSigningCertificate.ps1 -ExportCerPath C:\lab\mina-lab-signing.cer

.NOTES
    Run as the account that will run Build-MinaEndpointPackage.ps1: the certificate is created in
    CurrentUser\My and the build reads it from there.
#>
[CmdletBinding()]
param(
    [Parameter()] [string] $Subject       = 'CN=Mina Lab Code Signing (NOT FOR PRODUCTION)',
    [Parameter()] [int]    $ValidYears    = 2,
    [Parameter()] [string] $ExportCerPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host ''
Write-Host '  This creates a LAB signing certificate standing in for A6 (a real production code-signing'
Write-Host '  certificate). Anything signed with it is trusted only on machines where this'
Write-Host '  certificate has been deliberately added to the trust stores. Never use it for a'
Write-Host '  package that will reach a production endpoint.'
Write-Host ''

$existing = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $Subject }
if ($existing) {
    Write-Host ('An existing lab certificate with this subject was found ({0} of them):' -f @($existing).Count)
    foreach ($c in @($existing)) {
        Write-Host ('    {0}  expires {1:yyyy-MM-dd}' -f $c.Thumbprint, $c.NotAfter)
    }
    Write-Host ''
    Write-Host '  Reuse one of the thumbprints above rather than creating another, unless it has'
    Write-Host '  expired -- several certificates with the same subject make it ambiguous which one'
    Write-Host '  actually signed a given build.'
    Write-Host ''
}

$cert = New-SelfSignedCertificate `
    -Subject $Subject `
    -Type CodeSigningCert `
    -KeyUsage DigitalSignature `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -CertStoreLocation Cert:\CurrentUser\My `
    -NotAfter (Get-Date).AddYears($ValidYears) `
    -KeyExportPolicy NonExportable

Write-Host ('Created code-signing certificate.')
Write-Host ('    Subject    : {0}' -f $cert.Subject)
Write-Host ('    Thumbprint : {0}' -f $cert.Thumbprint)
Write-Host ('    Expires    : {0:yyyy-MM-dd}' -f $cert.NotAfter)
Write-Host ('    Store      : Cert:\CurrentUser\My  (private key non-exportable)')

if ($ExportCerPath) {
    $dir = Split-Path -Parent $ExportCerPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Export-Certificate -Cert $cert -FilePath $ExportCerPath -Force | Out-Null
    Write-Host ('    Public cert: {0}' -f $ExportCerPath)
    Write-Host ''
    Write-Host '  To make signatures from this certificate validate on a LAB endpoint, import the'
    Write-Host '  exported .cer there into both stores (run elevated on that machine):'
    Write-Host ''
    Write-Host ('      Import-Certificate -FilePath <path>\{0} -CertStoreLocation Cert:\LocalMachine\Root' -f (Split-Path -Leaf $ExportCerPath))
    Write-Host ('      Import-Certificate -FilePath <path>\{0} -CertStoreLocation Cert:\LocalMachine\TrustedPublisher' -f (Split-Path -Leaf $ExportCerPath))
    Write-Host ''
    Write-Host '  Root alone is not enough for a package whose scripts run under AllSigned, and'
    Write-Host '  TrustedPublisher alone is not enough for a chain that does not terminate in a'
    Write-Host '  trusted root -- a self-signed certificate needs both.'
}

Write-Host ''
Write-Host ('Build with:  .\Build-MinaEndpointPackage.ps1 -ConfigPath <config> -SigningCertificateThumbprint {0}' -f $cert.Thumbprint)
Write-Host ''

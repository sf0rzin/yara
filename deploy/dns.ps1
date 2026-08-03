#Requires -Version 5.1
<#
.SYNOPSIS
  Creates or updates the A and AAAA records for yara.rindexx.cc.

.DESCRIPTION
  Idempotent: run it again after the origin's address changes and it updates in
  place rather than duplicating.

  Records are created PROXIED, matching ayla.rindexx.cc. This is not optional
  here: the origin's nftables only accepts 80/443 from Cloudflare's ranges, so
  a grey-clouded record points at a host that will not answer it.

  Proxying does mean Cloudflare terminates TLS and sees plaintext requests.
  Vault items stay opaque — they are ciphertext at the application layer — but
  anything in a header is visible to it, which is why the sync protocol signs
  requests instead of carrying a bearer token. See docs/hosting.md.

  Client addresses survive the hop: Cloudflare sends CF-Connecting-IP, ayla's
  Caddy trusts it, and the origin trusts ayla. Both halves of that chain have
  to stay configured or {client_ip} becomes forgeable.

.NOTES
  The token is read from the environment and never taken as an argument,
  because arguments land in PSReadLine history.

      $env:CLOUDFLARE_API_TOKEN = (Get-Content $HOME\OneDrive\Desktop\cloudflare.txt |
        Where-Object { $_ -like 'write_all=*' }) -replace '^write_all=', ''

  Clear it when you are done:

      Remove-Item Env:\CLOUDFLARE_API_TOKEN

  A token scoped to Zone:DNS:Edit on rindexx.cc alone is enough for this. An
  account-wide write token is a much larger blast radius than two DNS records
  justify.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Ipv4,
  [string]$Ipv6,
  [string]$Zone   = 'rindexx.cc',
  [string]$Record = 'yara.rindexx.cc',
  # Only for an origin that is reachable directly. Read the note above first.
  [switch]$Unproxied
)

$ErrorActionPreference = 'Stop'

$token = $env:CLOUDFLARE_API_TOKEN
if ([string]::IsNullOrWhiteSpace($token)) {
  throw 'Set $env:CLOUDFLARE_API_TOKEN first. See the notes in this script.'
}

$api     = 'https://api.cloudflare.com/client/v4'
$headers = @{ Authorization = "Bearer $token" }

function Invoke-Cf {
  param([string]$Method, [string]$Path, $Body)

  $args = @{
    Method      = $Method
    Uri         = "$api$Path"
    Headers     = $headers
    ContentType = 'application/json'
  }
  if ($null -ne $Body) { $args.Body = ($Body | ConvertTo-Json -Depth 5 -Compress) }

  $response = Invoke-RestMethod @args
  if (-not $response.success) {
    # Surface Cloudflare's own message; its error codes are far more useful
    # than the HTTP status, which is 400 for almost everything.
    throw ($response.errors | ForEach-Object { "$($_.code): $($_.message)" }) -join '; '
  }
  $response.result
}

$zoneId = (Invoke-Cf GET "/zones?name=$Zone").id
if (-not $zoneId) { throw "Zone $Zone not found, or this token cannot see it." }

function Set-Record {
  param([string]$Type, [string]$Content)

  $proxied = -not $Unproxied
  $existing = Invoke-Cf GET "/zones/$zoneId/dns_records?type=$Type&name=$Record"
  $body = @{
    type    = $Type
    name    = $Record
    content = $Content
    # Cloudflare ignores TTL on proxied records; it is here for the grey-cloud
    # case, where a short value keeps a cutover from stalling behind caches.
    ttl     = 300
    proxied = $proxied
  }

  if ($existing) {
    if ($existing.content -eq $Content -and $existing.proxied -eq $proxied) {
      Write-Host "$Type $Record already correct"
      return
    }
    Invoke-Cf PUT "/zones/$zoneId/dns_records/$($existing.id)" $body | Out-Null
    Write-Host "$Type $Record updated -> $Content"
  }
  else {
    Invoke-Cf POST "/zones/$zoneId/dns_records" $body | Out-Null
    Write-Host "$Type $Record created -> $Content"
  }
}

Set-Record -Type 'A' -Content $Ipv4
if ($Ipv6) { Set-Record -Type 'AAAA' -Content $Ipv6 }

Write-Host ''
Write-Host 'Done. Verify before pointing Caddy at it:'
Write-Host "  Resolve-DnsName $Record -Type A"

param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$MavenArgs
)
$ErrorActionPreference = "Stop"
if (-not $env:AWS_ENDPOINT_URL -and -not $env:FLOCI_ENDPOINT) {
  Write-Error "Set AWS_ENDPOINT_URL (or FLOCI_ENDPOINT) to a CTF Compose instance."
}
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $Root
& .\mvnw.cmd install -DskipTests -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& .\mvnw.cmd -f tools/fuzz/pom.xml test "-Pfuzz-operator" @MavenArgs
exit $LASTEXITCODE

param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$MavenArgs
)
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $Root
& .\mvnw.cmd install -DskipTests -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& .\mvnw.cmd -f tools/fuzz/pom.xml test @MavenArgs
exit $LASTEXITCODE

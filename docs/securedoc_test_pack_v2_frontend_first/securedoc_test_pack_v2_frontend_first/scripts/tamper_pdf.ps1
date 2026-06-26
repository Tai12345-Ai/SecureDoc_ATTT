param(
  [Parameter(Mandatory=$true)][string]$InputPdf,
  [Parameter(Mandatory=$true)][string]$OutputPdf
)
$bytes = [System.IO.File]::ReadAllBytes($InputPdf)
if ($bytes.Length -lt 20) { throw "File too small to tamper safely" }
$pos = [Math]::Max(10, [Math]::Min([int]($bytes.Length / 2), $bytes.Length - 11))
$bytes[$pos] = ($bytes[$pos] + 1) % 256
[System.IO.File]::WriteAllBytes($OutputPdf, $bytes)
Write-Host "Tampered byte offset $pos; wrote $OutputPdf"

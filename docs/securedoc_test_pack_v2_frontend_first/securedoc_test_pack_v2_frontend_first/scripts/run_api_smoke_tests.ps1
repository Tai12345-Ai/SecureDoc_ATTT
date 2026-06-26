# Requires PowerShell 7+ because Invoke-RestMethod -Form is used.
param([string]$BaseUrl = "http://127.0.0.1:8000")
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Inputs = Join-Path $Root "inputs"
$Outputs = Join-Path $Root "outputs"
New-Item -ItemType Directory -Force -Path $Outputs | Out-Null

function Step($name) { Write-Host "`n=== $name ===" -ForegroundColor Cyan }

Step "Health"
$health = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/health"
$health | ConvertTo-Json -Depth 5

Step "Init and issue active demo cert"
Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/certificates/init-demo-pki?force=true" | Out-Null
$cert = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/certificates/enroll-demo-backend-key?activate=true"
$serial = $cert.serial
Write-Host "SERIAL=$serial"

Step "Canonical payload sign-and-verify"
$txt = Join-Path $Inputs "04_plain_text_for_canonical_payload.txt"
$prep = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/user-signing/prepare" -Form @{ file = Get-Item $txt; signing_purpose = "Ky xac nhan tai lieu text"; certificate_serial = $serial; digest_algorithm = "sha256" }
$req = $prep.request_id
Write-Host "REQ_ID=$req"
Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/user-signing/confirm?request_id=$req" | ConvertTo-Json -Depth 4
$canon = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/user-signing/sign-and-verify?request_id=$req"
$canon | ConvertTo-Json -Depth 6

Step "PDF/PAdES sign and verify"
$pdf = Join-Path $Inputs "01_contract_basic_unsigned.pdf"
$prep2 = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/user-signing/prepare" -Form @{ file = Get-Item $pdf; signing_purpose = "Ky hop dong demo"; certificate_serial = $serial; digest_algorithm = "sha256" }
$req2 = $prep2.request_id
Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/user-signing/confirm?request_id=$req2" | Out-Null
$signed = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/user-signing/sign-pdf?request_id=$req2"
$fileId = $signed.file_id
Write-Host "FILE_ID=$fileId"
$signed | ConvertTo-Json -Depth 7
$signedPdf = Join-Path $Outputs "signed_01_contract.pdf"
Invoke-WebRequest -Uri "$BaseUrl/api/user-signing/signed-files/$fileId" -OutFile $signedPdf
Write-Host "Downloaded $signedPdf"
$verify = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/verification/verify-pdf" -Form @{ file = Get-Item $signedPdf }
$verify | ConvertTo-Json -Depth 7

Step "Tamper and verify rejection"
$tampered = Join-Path $Outputs "signed_01_contract_tampered.pdf"
python (Join-Path $PSScriptRoot "tamper_pdf.py") $signedPdf $tampered
try {
  $bad = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/verification/verify-pdf" -Form @{ file = Get-Item $tampered }
  $bad | ConvertTo-Json -Depth 7
  if ($bad.accepted -eq $true) { throw "Tampered PDF was unexpectedly accepted" }
} catch {
  Write-Host "Tampered verification failed as expected: $($_.Exception.Message)" -ForegroundColor Yellow
}

Step "Timestamp"
$imprint = "a" * 64
$token = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/timestamp/issue" -ContentType "application/json" -Body (@{ message_imprint_sha256 = $imprint } | ConvertTo-Json)
$tsVerify = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/timestamp/verify" -ContentType "application/json" -Body (@{ token = $token; expected_imprint_sha256 = $imprint } | ConvertTo-Json -Depth 8)
$tsVerify | ConvertTo-Json -Depth 8

Step "Blind signature all-in-one"
$blind = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/blind-signature/run" -ContentType "application/json" -Body (@{ message = "privacy-token-demo-$(Get-Date -Format yyyyMMddHHmmss)" } | ConvertTo-Json)
$blind | ConvertTo-Json -Depth 8

Step "Audit"
Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/audit/events?limit=20" | ConvertTo-Json -Depth 8

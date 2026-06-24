"""Create a tampered copy of a signed PDF for SecureDoc negative verification tests.
Usage: python scripts/tamper_signed_pdf.py path/to/signed.pdf
Output: path/to/signed_tampered.pdf
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    print("Usage: python scripts/tamper_signed_pdf.py path/to/signed.pdf")
    raise SystemExit(2)

src = Path(sys.argv[1])
if not src.exists():
    print(f"File not found: {src}")
    raise SystemExit(1)

data = bytearray(src.read_bytes())
if len(data) < 50:
    print("File is too small to tamper safely")
    raise SystemExit(1)

# Flip one byte near the end. This usually preserves the .pdf extension and file shape,
# but invalidates the cryptographic signature/coverage checks.
index = max(0, len(data) - 200)
data[index] = (data[index] + 1) % 255
out = src.with_name(src.stem + "_tampered.pdf")
out.write_bytes(data)
print(out)

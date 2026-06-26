#!/usr/bin/env python3
"""Create a tampered copy of a signed PDF by flipping one byte near the middle.
Usage: python tamper_pdf.py signed.pdf signed_tampered.pdf
"""
import sys
from pathlib import Path

if len(sys.argv) != 3:
    print("Usage: python tamper_pdf.py <input_signed_pdf> <output_tampered_pdf>")
    sys.exit(2)

inp = Path(sys.argv[1])
out = Path(sys.argv[2])
data = bytearray(inp.read_bytes())
if len(data) < 20:
    raise SystemExit("File too small to tamper safely")
# Avoid first/last 10 bytes so the file is more likely to remain parseable.
pos = max(10, min(len(data) // 2, len(data) - 11))
data[pos] = (data[pos] + 1) % 256
out.write_bytes(data)
print(f"Tampered byte offset {pos}; wrote {out}")

# SecureDoc_ATTT Test Pack v2 — Frontend-first

# SecureDoc test pack v1

This pack contains unsigned PDF inputs, invalid inputs, and helper scripts for testing SecureDoc_ATTT.

## Folders
- `inputs/`: files to upload in the UI or API tests.
- `scripts/`: helper scripts for API smoke flow and tamper tests.
- `collections/`: Postman collection skeleton.
- `outputs/`: empty folder for downloaded signed PDFs and tampered copies.

## Assumed local services
Backend: `http://127.0.0.1:8000`
Frontend: `http://localhost:5173`

Start backend from the repo root:

```powershell
cd securedoc_full_demo_v4
.\.venv\Scripts\activate
cd backend
$env:PYTHONPATH="."
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Recommended API docs: `http://127.0.0.1:8000/docs`

## Main manual order
1. Init demo PKI / issue active demo certificate.
2. Test canonical payload signing with `04_plain_text_for_canonical_payload.txt`.
3. Test PDF/PAdES signing with `01_contract_basic_unsigned.pdf`.
4. Download signed PDF to `outputs/`.
5. Verify signed PDF.
6. Tamper the signed PDF with `scripts/tamper_pdf.py`, then verify again; expected result is rejection.
7. Test timestamp, revocation, remote signing, blind signature, audit, and negative cases from `TEST_CASE_MATRIX.md`.


## Frontend-first test plan

Bản v2 ưu tiên kiểm thử UI trước. Mở file `FRONTEND_FIRST_TEST_PLAN.md` để chạy theo thứ tự:

1. Frontend/manual UI tests: FE-00 đến FE-19.
2. Backend/API đối chiếu: BE-01 đến BE-10.
3. Dùng `TEST_CASE_MATRIX.md` khi cần test API chi tiết hơn.


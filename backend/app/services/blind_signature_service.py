"""
Blind Signature Service.

Baseline:
- PyCryptodome: low-level RSA arithmetic for blind RSA demo.
- Cashu Nutshell: reference architecture for privacy token / mint / wallet / Chaumian ecash.

This demo implements educational blind RSA:

message/token -> blind(message) -> signer signs blinded message -> unblind(signature) -> verify(message, signature)

Important:
- This is not document signing.
- This is for unlinkability/privacy.
- Do not reuse CA/TSA/document-signing keys for blind signing.
"""

_BLIND_SIGNER_KEY = None


def _load_pycryptodome():
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Util.number import bytes_to_long, inverse
        from Crypto.Hash import SHA256
        from Crypto.Random import random
    except ModuleNotFoundError as exc:
        raise RuntimeError("PyCryptodome is required for Blind Signature Mode. Install requirements.txt first.") from exc
    return RSA, bytes_to_long, inverse, SHA256, random


def _blind_signer_key():
    global _BLIND_SIGNER_KEY
    RSA, _, _, _, _ = _load_pycryptodome()
    if _BLIND_SIGNER_KEY is None:
        _BLIND_SIGNER_KEY = RSA.generate(2048)
    return _BLIND_SIGNER_KEY

def run_blind_signature_flow(message: str) -> dict:
    _, bytes_to_long, inverse, SHA256, random = _load_pycryptodome()
    blind_signer_key = _blind_signer_key()
    public_key = blind_signer_key.publickey()
    message_bytes = message.encode("utf-8")
    message_hash = SHA256.new(message_bytes).digest()
    m = bytes_to_long(message_hash)
    n = public_key.n
    e = public_key.e

    while True:
        r = random.StrongRandom().randint(2, n - 1)
        try:
            r_inv = inverse(r, n)
            break
        except ValueError:
            continue

    blinded = (m * pow(r, e, n)) % n
    blind_signature = pow(blinded, blind_signer_key.d, blind_signer_key.n)
    unblinded_signature = (blind_signature * r_inv) % n
    recovered = pow(unblinded_signature, e, n)
    verified = recovered == m

    return {
        "title": "Blind signature verified" if verified else "Blind signature failed",
        "message": "Signer ký bản đã làm mù; verifier vẫn xác minh được chữ ký trên token gốc.",
        "steps": [
            {
                "name": "Create token",
                "explanation": "User tạo token/message cần được ký ẩn danh.",
                "value": message,
            },
            {
                "name": "Blind token",
                "explanation": "User nhân hash token với r^e mod n để signer không nhìn thấy token gốc.",
                "value": str(blinded)[:48] + "...",
            },
            {
                "name": "Blind signer signs",
                "explanation": "Blind signer ký blinded token bằng private key riêng của blind service.",
                "value": str(blind_signature)[:48] + "...",
            },
            {
                "name": "Unblind signature",
                "explanation": "User loại bỏ blinding factor để nhận chữ ký hợp lệ trên token gốc.",
                "value": str(unblinded_signature)[:48] + "...",
            },
            {
                "name": "Verify",
                "explanation": "Verifier dùng public key của blind signer để kiểm tra chữ ký trên token gốc.",
                "value": "valid" if verified else "invalid",
            },
        ],
        "verified": verified,
        "unlinkability_note": "Signer chỉ thấy blinded token, nên khó liên kết yêu cầu ký ban đầu với token đã unblind sau này.",
        "advanced": {
            "scheme": "Educational blind RSA",
            "messageHashSha256": message_hash.hex(),
            "publicExponent": e,
            "modulusBits": public_key.size_in_bits(),
            "warning": "Demo only. Production privacy token should use a reviewed protocol and double-spend protection.",
        },
    }

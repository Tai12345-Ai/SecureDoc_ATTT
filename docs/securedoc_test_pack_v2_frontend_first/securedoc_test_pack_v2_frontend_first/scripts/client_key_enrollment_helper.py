#!/usr/bin/env python3
"""Generate a CLIENT_SIDE_KEY enrollment proof for SecureDoc.

Usage:
  python client_key_enrollment_helper.py --base-url http://127.0.0.1:8000 --name "Client Test" --email client@example.com

Requires: cryptography, requests.
Run inside the repo venv after `pip install -r requirements.txt`; install requests if needed.
"""
import argparse, base64, json, sys
try:
    import requests
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
except Exception as exc:
    raise SystemExit(f"Missing dependency: {exc}")

p = argparse.ArgumentParser()
p.add_argument('--base-url', default='http://127.0.0.1:8000')
p.add_argument('--name', default='Client Side Test Signer')
p.add_argument('--email', default='client-side@example.com')
args = p.parse_args()

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
private_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
open('client_side_private_key.pem','w',encoding='utf-8').write(private_pem)
open('client_side_public_key.pem','w',encoding='utf-8').write(public_pem)

challenge_resp = requests.post(f"{args.base_url}/api/key-enrollment/challenge", json={
    'display_name': args.name,
    'email': args.email,
    'public_key_pem': public_pem,
})
print('challenge status:', challenge_resp.status_code)
print(challenge_resp.text)
challenge_resp.raise_for_status()
challenge = challenge_resp.json()['challenge']
challenge_id = challenge_resp.json()['challenge_id']
sig = key.sign(challenge.encode('utf-8'), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
proof_b64 = base64.b64encode(sig).decode('ascii')
submit_resp = requests.post(f"{args.base_url}/api/key-enrollment/submit-public-key", json={
    'challenge_id': challenge_id,
    'proof_signature_base64': proof_b64,
    'issue_certificate': True,
    'activate_certificate': True,
})
print('submit status:', submit_resp.status_code)
print(json.dumps(submit_resp.json(), indent=2, ensure_ascii=False))

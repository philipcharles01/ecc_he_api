from flask import Flask, request, jsonify
import boto3, uuid, os, base64, json, random
from ecies.keys import PrivateKey
from ecies import encrypt, decrypt

app = Flask(__name__)
app.config['DEBUG'] = True  # Enables detailed logs

s3 = boto3.client(...)

@app.before_request
def log_request():
    app.logger.debug(f"Headers: {dict(request.headers)}")
    app.logger.debug(f"Raw body: {request.get_data().decode(errors='ignore')}")

@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    ...  # retains existing logic

@app.route('/get_private_key/<key_id>', methods=['GET'])
def get_private_key(key_id):
    ...  # retains existing logic

@app.route('/decrypt_with_private_key', methods=['POST'])
def decrypt_with_private_key():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid or missing JSON"}), 400

    enc_b64 = data.get('ecc_encrypted_value', '')
    private_key_hex = data.get('private_key', '').strip()
    app.logger.debug(f"Private key received (raw): '{private_key_hex}', length={len(private_key_hex)}")

    # Pad odd-length hex
    if len(private_key_hex) % 2 != 0:
        private_key_hex = private_key_hex.zfill(len(private_key_hex) + 1)
        app.logger.debug(f"Padded private key: '{private_key_hex}', new length={len(private_key_hex)}")

    try:
        encrypted_bytes = base64.b64decode(enc_b64)
        decrypted = decrypt(private_key_hex, encrypted_bytes)
        return jsonify({"decrypted_value": decrypted.decode()})
    except Exception as e:
        app.logger.exception("ECC Decryption failed")
        return jsonify({"error": f"❌ ECC Decryption failed: {e}"}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt_homomorphic():
    ...  # retains existing logic

if __name__ == '__main__':
    app.run(debug=True)

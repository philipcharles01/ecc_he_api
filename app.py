from flask import Flask, request, jsonify
import boto3
import uuid
import os
import base64
import json
import random

from Crypto.PublicKey import ECC
from ecies.utils import generate_key
from ecies import encrypt, decrypt

app = Flask(__name__)

# ✅ AWS S3 Configuration
s3 = boto3.client('s3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name='us-east-1'
)
BUCKET_NAME = 'ecc-key-store-123'  # ✅ Replace with your real S3 bucket

# ✅ Home Route
@app.route('/')
def home():
    return "✅ ECC + Homomorphic Encryption API is working!"

# ✅ ENCRYPT ROUTE
@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    data = request.get_json()
    value = str(data.get('value', ''))

    # ✅ ECC Key Generation
    ecc_private = generate_key()
    ecc_private_hex = ecc_private.to_hex()
    ecc_public_hex = ecc_private.public_key.format(True).hex()

    ecc_encrypted = encrypt(bytes.fromhex(ecc_public_hex), value.encode())
    ecc_encrypted_b64 = base64.b64encode(ecc_encrypted).decode()

    # ✅ Homomorphic Encryption
    homo_key = random.randint(1, 100)
    try:
        encrypted_value = float(value) + homo_key
    except:
        encrypted_value = base64.b64encode(value.encode()).decode() + "::KEY::" + str(homo_key)

    # ✅ Store in AWS
    key_id = str(uuid.uuid4())
    key_data = {
        "private_key": ecc_private_hex
    }

    try:
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=f"{key_id}.json",
            Body=json.dumps(key_data),
            ContentType='application/json'
        )
    except Exception as e:
        return jsonify({"error": f"❌ Failed to store private key: {str(e)}"}), 500

    return jsonify({
        "key_id": key_id,
        "public_key": ecc_public_hex,
        "private_key": ecc_private_hex,
        "homo_key": homo_key,
        "encrypted_value": encrypted_value,
        "ecc_encrypted_value": ecc_encrypted_b64,
        "status": "✅ Encrypted and stored"
    })

# ✅ GET PRIVATE KEY ROUTE
@app.route('/get_private_key/<key_id>', methods=['GET'])
def get_private_key(key_id):
    try:
        response = s3.get_object(Bucket=BUCKET_NAME, Key=f"{key_id}.json")
        content = json.loads(response['Body'].read().decode('utf-8'))
        return jsonify({"private_key": content["private_key"]})
    except Exception as e:
        return jsonify({"error": f"❌ Key not found: {str(e)}"}), 404

# ✅ HOMOMORPHIC DECRYPT
@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    data = request.get_json()
    try:
        encrypted_value = float(data.get('encrypted_value'))
        homo_key = int(data.get('homo_key'))
        decrypted = encrypted_value - homo_key
        return jsonify({'decrypted_value': decrypted})
    except Exception as e:
        return jsonify({'error': f"❌ Homomorphic Decryption Failed: {str(e)}"}), 400

# ✅ ECC DECRYPT ROUTE
@app.route('/decrypt_with_private_key', methods=['POST'])
def decrypt_with_private_key():
    data = request.get_json()
    enc_b64 = data.get('ecc_encrypted_value')
    private_key_hex = data.get('private_key')

    try:
        encrypted_bytes = base64.b64decode(enc_b64)
        decrypted = decrypt(private_key_hex, encrypted_bytes)
        return jsonify({'decrypted_value': decrypted.decode()})
    except Exception as e:
        return jsonify({'error': f"❌ ECC Decryption failed: {str(e)}"}), 400

if __name__ == '__main__':
    app.run(debug=True)

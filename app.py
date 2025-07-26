from flask import Flask, request, jsonify
import boto3
import uuid
from Crypto.PublicKey import ECC
import random
import os
import base64

app = Flask(__name__)

# ✅ AWS S3 Configuration (use your environment variables)
s3 = boto3.client('s3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name='us-east-1'
)
BUCKET_NAME = 'ecc-key-store-123'

# 🔐 Simulated Homomorphic Encryption for strings & numbers
def simple_homomorphic_encrypt(value, key):
    try:
        num = float(value)
        return num + key
    except ValueError:
        encoded = base64.b64encode(value.encode()).decode()
        return f"{encoded}::KEY::{key}"

def simple_homomorphic_decrypt(ciphertext, key):
    if isinstance(ciphertext, (int, float)):
        return ciphertext - key
    try:
        encoded, _, k = ciphertext.partition("::KEY::")
        if int(k) == key:
            return base64.b64decode(encoded.encode()).decode()
        else:
            return "Key mismatch"
    except Exception:
        return "Invalid format"

@app.route('/')
def home():
    return "✅ Flask ECC + Homomorphic Encryption API is running!"

@app.route('/generate_keys', methods=['GET'])
def generate_keys():
    key = ECC.generate(curve='P-256')
    private_key = key.export_key(format='PEM')
    public_key = key.public_key().export_key(format='PEM')
    return jsonify({
        'private_key': private_key,
        'public_key': public_key
    })

@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    data = request.get_json()
    value = str(data.get('value', ''))

    ecc_key = ECC.generate(curve='P-256')
    private_key = ecc_key.export_key(format='PEM')
    public_key = ecc_key.public_key().export_key(format='PEM')

    homo_key = random.randint(1, 100)
    encrypted_value = simple_homomorphic_encrypt(value, homo_key)

    key_id = str(uuid.uuid4())
    s3.put_object(Bucket=BUCKET_NAME, Key=key_id, Body=private_key)

    return jsonify({
        'encrypted_value': encrypted_value,
        'homo_key': homo_key,
        'public_key': public_key,
        'key_id': key_id
    })

@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    data = request.get_json()
    ciphertext = data.get('encrypted_value', '')
    key = int(data.get('homo_key', 0))

    decrypted_value = simple_homomorphic_decrypt(ciphertext, key)
    return jsonify({'decrypted_value': decrypted_value})

@app.route('/get_private_key/<key_id>', methods=['GET'])
def get_private_key(key_id):
    try:
        response = s3.get_object(Bucket=BUCKET_NAME, Key=key_id)
        private_key = response['Body'].read().decode('utf-8')
        return jsonify({'private_key': private_key})
    except Exception as e:
        return jsonify({'error': str(e)}), 404

if __name__ == '__main__':
    app.run(debug=True)

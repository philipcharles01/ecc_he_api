from flask import Flask, request, jsonify
import boto3
import uuid
from Crypto.PublicKey import ECC
import random
import os
import base64
import json

app = Flask(__name__)

# ✅ AWS S3 Configuration
s3 = boto3.client('s3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name='us-east-1'
)
BUCKET_NAME = 'ecc-key-store-123'  # ✅ Replace with your real bucket name

# 🔐 Simple Homomorphic Encryption (demo only)
def simple_homomorphic_encrypt(value, key):
    try:
        num = float(value)
        return num + key
    except ValueError:
        encoded = base64.b64encode(value.encode()).decode()
        return f"{encoded}::KEY::{key}"

# ✅ Home Test Endpoint
@app.route('/')
def home():
    return "✅ Flask ECC + Homomorphic Encryption API is running!"

# ✅ ENCRYPTION + KEY STORAGE
@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    data = request.get_json()
    value = str(data.get('value', ''))

    # ✅ Generate ECC Key Pair
    ecc_key = ECC.generate(curve='P-256')
    private_key = ecc_key.export_key(format='PEM')
    public_key = ecc_key.public_key().export_key(format='PEM')

    # ✅ Homomorphic Encryption Key
    homo_key = random.randint(1, 100)
    encrypted_value = simple_homomorphic_encrypt(value, homo_key)

    # ✅ Generate unique Key ID
    key_id = str(uuid.uuid4())

    # ✅ Convert private key to JSON
    key_json = json.dumps({"private_key": private_key})

    try:
        # ✅ Upload JSON to S3 (filename = key_id.json)
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=f"{key_id}.json",
            Body=key_json,
            ContentType='application/json'
        )

        return jsonify({
            'encrypted_value': encrypted_value,
            'homo_key': homo_key,
            'public_key': public_key,
            'private_key': private_key,
            'key_id': key_id,
            'status': '✅ Private key stored in AWS as JSON'
        })
    except Exception as e:
        return jsonify({'error': f"❌ Failed to store private key: {str(e)}"}), 500

# ✅ RETRIEVE KEY BY ID
@app.route('/get_private_key/<key_id>', methods=['GET'])
def get_private_key(key_id):
    try:
        response = s3.get_object(Bucket=BUCKET_NAME, Key=f"{key_id}.json")
        key_data = json.loads(response['Body'].read().decode('utf-8'))
        return jsonify({'private_key': key_data['private_key']})
    except Exception as e:
        return jsonify({'error': str(e)}), 404

if __name__ == '__main__':
    app.run(debug=True)

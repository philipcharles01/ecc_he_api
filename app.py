from flask import Flask, request, jsonify
import boto3
import uuid
from Crypto.PublicKey import ECC
import random
import os

app = Flask(__name__)

# ✅ AWS S3 Configuration (Secure via Environment Variables)
s3 = boto3.client('s3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name='us-east-1'
)
BUCKET_NAME = 'ecc-key-store-123'

# 🔐 Simulated Homomorphic Encryption
def simple_homomorphic_encrypt(value, key):
    return value + key

def simple_homomorphic_decrypt(ciphertext, key):
    return ciphertext - key

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
    value = int(data.get('value', 0))

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
    ciphertext = int(data.get('encrypted_value', 0))
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

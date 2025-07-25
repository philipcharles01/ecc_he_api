from flask import Flask, request, jsonify
import boto3
import uuid
from Crypto.PublicKey import ECC
import json
import random

app = Flask(__name__)

# Fake homomorphic encryption function (demo only)
def simple_homomorphic_encrypt(value, key):
    return value + key

def simple_homomorphic_decrypt(ciphertext, key):
    return ciphertext - key

@app.route('/')
def home():
    return "Flask ECC + Homomorphic Encryption API is running!"

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
    key = random.randint(1, 100)

    encrypted = simple_homomorphic_encrypt(value, key)

    return jsonify({
        'encrypted_value': encrypted,
        'homo_key': key  # This key is needed to decrypt
    })

@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    data = request.get_json()
    ciphertext = int(data.get('encrypted_value', 0))
    key = int(data.get('homo_key', 0))

    decrypted = simple_homomorphic_decrypt(ciphertext, key)

    return jsonify({
        'decrypted_value': decrypted
    })


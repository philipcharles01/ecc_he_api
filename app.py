from flask import Flask, request, jsonify
import boto3, uuid, os, base64, json, random
from ecies import encrypt, decrypt
from ecies.utils import generate_key
import logging

app = Flask(__name__)
app.config['DEBUG'] = True

# Enable debug-level logging
logging.basicConfig(level=logging.DEBUG)

# Initialize S3 client
s3 = boto3.client(
    's3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name='us-east-1'
)
BUCKET_NAME = 'ecc-key-store-123'

@app.before_request
def log_request():
    app.logger.debug(f"--- Request to {request.path} ---")
    app.logger.debug(f"Headers: {dict(request.headers)}")
    raw = request.get_data().decode(errors='ignore')
    app.logger.debug(f"Raw body: {raw}")

@app.route('/')
def home():
    return "✅ ECC + Homomorphic Encryption API is working!"

@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400

    value = str(data.get('value', ''))

    # Generate ECC keypair
    key = generate_key()
    sk_hex = key.to_hex()
    pk_hex = key.public_key.format(True).hex()

    # ECC encryption
    cipher_bytes = encrypt(bytes.fromhex(pk_hex), value.encode())
    ecc_encrypted_b64 = base64.b64encode(cipher_bytes).decode()

    # Homomorphic-style encryption (simple obfuscation)
    homo_key = random.randint(1, 100)
    try:
        encrypted_value = float(value) + homo_key
    except:
        encrypted_value = base64.b64encode(value.encode()).decode() + "::KEY::" + str(homo_key)

    # Upload private key to S3
    key_id = str(uuid.uuid4())
    s3.put_object(
        Bucket=BUCKET_NAME,
        Key=f"{key_id}.json",
        Body=json.dumps({'private_key': sk_hex}),
        ContentType='application/json'
    )

    return jsonify({
        'key_id': key_id,
        'public_key': pk_hex,
        'homo_key': homo_key,
        'encrypted_value': encrypted_value,
        'ecc_encrypted_value': ecc_encrypted_b64,
        'status': '✅ Encrypted and stored'
    })

@app.route('/get_private_key/<key_id>', methods=['GET'])
def get_private_key(key_id):
    try:
        obj = s3.get_object(Bucket=BUCKET_NAME, Key=f"{key_id}.json")
        content = json.loads(obj['Body'].read().decode())
        return jsonify({'private_key': content['private_key']})
    except Exception as e:
        return jsonify({'error': f'❌ Key not found: {e}'}), 404

@app.route('/decrypt_with_private_key', methods=['POST'])
def decrypt_with_private_key():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid or missing JSON'}), 400

    enc_b64 = data.get('ecc_encrypted_value', '')
    private_key_hex = data.get('private_key', '').strip()

    try:
        encrypted_bytes = base64.b64decode(enc_b64)
        decrypted_bytes = decrypt(private_key_hex, encrypted_bytes)
        return jsonify({'decrypted_value': decrypted_bytes.decode()})
    except Exception as e:
        app.logger.exception("ECC Decryption failed")
        return jsonify({'error': f'❌ ECC Decryption failed: {e}'}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt_homomorphic():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    try:
        encrypted_value = float(data.get('encrypted_value'))
        homo_key = int(data.get('homo_key'))
        return jsonify({'decrypted_value': encrypted_value - homo_key})
    except Exception as e:
        return jsonify({'error': f'❌ Homomorphic Decryption Failed: {e}'}), 400

if __name__ == '__main__':
    app.run(debug=True)

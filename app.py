from flask import Flask, request, jsonify
import boto3, uuid, os, base64, json, random
from ecies.keys import PrivateKey
from ecies import encrypt, decrypt
from datetime import datetime

app = Flask(__name__)
app.config['DEBUG'] = True

# ====== AWS S3 CONFIG ======
s3 = boto3.client(
    's3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name='us-east-1'
)
BUCKET_NAME = 'ecc-key-store-123'

# ====== Store latest sensor data in memory ======
latest_sensor_data = {}

# ====== DEBUG LOGGING ======
@app.before_request
def log_request():
    app.logger.debug(f"--- Request to {request.path} ---")
    app.logger.debug(f"Headers: {dict(request.headers)}")
    raw = request.get_data().decode(errors='ignore')
    app.logger.debug(f"Raw body: {raw}")

# ====== BASIC TEST ROUTE ======
@app.route('/')
def home():
    return "✅ ECC + Sensor API is running!"

# =================================================
# ========== ESP32 DATA HANDLING ROUTES ===========
# =================================================
@app.route('/update', methods=['POST'])
def update_data():
    """
    ESP32 will send: { "temp": 25.4, "hum": 60, "soil": 45 }
    Optionally encrypt before storing
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400

    # Optional: ECC encryption of each value
    sk = PrivateKey.generate()
    pk_hex = sk.public_key.to_hex(True)

    encrypted_data = {}
    for key, value in data.items():
        value_str = str(value)
        cipher_bytes = encrypt(pk_hex, value_str.encode())
        encrypted_data[key] = base64.b64encode(cipher_bytes).decode()

    # Store in memory with timestamp (plaintext & encrypted)
    global latest_sensor_data
    latest_sensor_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "plain": data,
        "public_key": pk_hex,
        "encrypted": encrypted_data,
        "private_key": sk.to_hex()  # In practice, store this securely
    }

    return jsonify({"status": "✅ Data received", "public_key": pk_hex})

@app.route('/get', methods=['GET'])
def get_data():
    """MIT App Inventor fetches latest readings"""
    if not latest_sensor_data:
        return jsonify({'error': 'No data available'}), 404
    return jsonify(latest_sensor_data)

# =================================================
# ========== ENCRYPTION/DECRYPTION ROUTES =========
# =================================================
@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    value = str(data.get('value', ''))

    sk = PrivateKey('secp256k1')
    sk_hex = sk.to_hex()
    pk_hex = sk.public_key.to_hex(True)

    cipher_bytes = encrypt(pk_hex, value.encode())
    ecc_encrypted_b64 = base64.b64encode(cipher_bytes).decode()

    homo_key = random.randint(1, 100)
    try:
        encrypted_value = float(value) + homo_key
    except:
        encrypted_value = base64.b64encode(value.encode()).decode() + "::KEY::" + str(homo_key)

    key_id = str(uuid.uuid4())
    key_data = {'private_key': sk_hex}
    s3.put_object(Bucket=BUCKET_NAME, Key=f"{key_id}.json",
                  Body=json.dumps(key_data), ContentType='application/json')

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
        resp = s3.get_object(Bucket=BUCKET_NAME, Key=f"{key_id}.json")
        content = json.loads(resp['Body'].read().decode())
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
    app.logger.debug(f"Private key received raw: '{private_key_hex}', length={len(private_key_hex)}")

    if len(private_key_hex) % 2 != 0:
        private_key_hex = private_key_hex.zfill(len(private_key_hex) + 1)
        app.logger.debug(f"Padded private key: '{private_key_hex}', new length={len(private_key_hex)}")

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
    app.run(host='0.0.0.0', port=8000, debug=True)

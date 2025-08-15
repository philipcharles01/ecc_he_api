from flask import Flask, request, jsonify
import boto3, uuid, os, base64, json, random
from ecies.keys import PrivateKey
from ecies import encrypt, decrypt

app = Flask(__name__)
app.config['DEBUG'] = True

# ================= AWS S3 SETUP =================
s3 = boto3.client(
    's3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name='us-east-1'
)
BUCKET_NAME = 'ecc-key-store-123'

# Store latest sensor data in memory
latest_sensor_data = {"temperature": None, "humidity": None, "soil": None}

# ================= LOGGING =================
@app.before_request
def log_request():
    app.logger.debug(f"--- Request to {request.path} ---")
    app.logger.debug(f"Headers: {dict(request.headers)}")
    raw = request.get_data().decode(errors='ignore')
    app.logger.debug(f"Raw body: {raw}")

# ================= HOME =================
@app.route('/')
def home():
    return "✅ ECC + Homomorphic Encryption API is working!"

# ================= ENCRYPT =================
@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    try:
        data = request.get_json(force=True)
        value = str(data.get('value', '')).replace('\r', '').replace('\n', '\\n')

        # ECC key generation
        sk = PrivateKey()  # generates new private key
        sk_hex = sk.to_hex()
        pk_hex = sk.public_key.to_hex(True)

        # ECC encryption
        cipher_bytes = encrypt(pk_hex, value.encode())
        ecc_encrypted_b64 = base64.b64encode(cipher_bytes).decode()

        # Homomorphic encryption
        homo_key = random.randint(1, 100)
        try:
            encrypted_value = float(value) + homo_key
        except:
            encrypted_value = base64.b64encode(value.encode()).decode() + "::KEY::" + str(homo_key)

        # Store private key in S3
        key_id = str(uuid.uuid4())
        key_data = {'private_key': sk_hex}
        try:
            s3.put_object(Bucket=BUCKET_NAME, Key=f"{key_id}.json",
                          Body=json.dumps(key_data), ContentType='application/json')
        except Exception as s3_err:
            app.logger.error(f"S3 Storage Failed: {s3_err}")

        return jsonify({
            'key_id': key_id,
            'public_key': pk_hex,
            'homo_key': homo_key,
            'encrypted_value': encrypted_value,
            'ecc_encrypted_value': ecc_encrypted_b64,
            'status': '✅ Encrypted and stored'
        })

    except Exception as e:
        app.logger.exception("Encryption Failed")
        return jsonify({'error': f'❌ Encryption Failed: {e}'}), 500

# ================= GET PRIVATE KEY BY KEY ID =================
@app.route('/get_private_key/<key_id>', methods=['GET'])
def get_private_key(key_id):
    """Retrieve private key from AWS S3 using key_id"""
    try:
        resp = s3.get_object(Bucket=BUCKET_NAME, Key=f"{key_id}.json")
        content = json.loads(resp['Body'].read().decode())
        return jsonify({'private_key': content['private_key']})
    except Exception as e:
        return jsonify({'error': f'❌ Key not found or S3 error: {e}'}), 404

# ================= ECC DECRYPT =================
@app.route('/decrypt_with_private_key', methods=['POST'])
def decrypt_with_private_key():
    try:
        data = request.get_json(force=True)
        enc_b64 = data.get('ecc_encrypted_value', '')
        private_key_hex = data.get('private_key', '').strip()

        if len(private_key_hex) % 2 != 0:
            private_key_hex = private_key_hex.zfill(len(private_key_hex) + 1)

        encrypted_bytes = base64.b64decode(enc_b64)
        decrypted_bytes = decrypt(private_key_hex, encrypted_bytes)
        return jsonify({'decrypted_value': decrypted_bytes.decode()})
    except Exception as e:
        app.logger.exception("ECC Decryption failed")
        return jsonify({'error': f'❌ ECC Decryption failed: {e}'}), 400

# ================= HOMOMORPHIC DECRYPT =================
@app.route('/decrypt', methods=['POST'])
def decrypt_homomorphic():
    try:
        data = request.get_json(force=True)
        encrypted_value = float(data.get('encrypted_value'))
        homo_key = int(data.get('homo_key'))
        return jsonify({'decrypted_value': encrypted_value - homo_key})
    except Exception as e:
        app.logger.exception("Homomorphic Decryption Failed")
        return jsonify({'error': f'❌ Homomorphic Decryption Failed: {e}'}), 400

# ================= ESP32 SEND SENSOR DATA =================
@app.route('/update', methods=['POST'])
def update_data():
    try:
        global latest_sensor_data
        data = request.get_json(force=True)
        latest_sensor_data = {
            "temperature": data.get("temperature"),
            "humidity": data.get("humidity"),
            "soil": data.get("soil")
        }
        return jsonify({"status": "✅ Data updated", "data": latest_sensor_data})
    except Exception as e:
        app.logger.exception("Sensor Data Update Failed")
        return jsonify({"error": f"❌ Sensor Update Failed: {e}"}), 400

# ================= MIT APP INVENTOR GET SENSOR DATA =================
@app.route('/get', methods=['GET'])
def get_data():
    if latest_sensor_data["temperature"] is None and \
       latest_sensor_data["humidity"] is None and \
       latest_sensor_data["soil"] is None:
        return jsonify({"error": "❌ No data sent from ESP32, check connection"})
    
    return jsonify(latest_sensor_data)

# ================= RENDER DEPLOYMENT ENTRY =================
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)

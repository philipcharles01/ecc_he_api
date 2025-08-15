from flask import Flask, request, jsonify
import boto3, uuid, os, base64, json, random
from ecies.keys import PrivateKey
from ecies import encrypt, decrypt

app = Flask(__name__)
app.config['DEBUG'] = True

# ================= AWS S3 SETUP =================
# Set these in Render → Environment
S3_BUCKET = os.getenv("S3_BUCKET", "ecc-key-store-123")
s3 = boto3.client(
    's3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID') or os.getenv('AWS_ACCESS_KEY'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY') or os.getenv('AWS_SECRET_KEY'),
    region_name=os.getenv('AWS_REGION', 'us-east-1')
)

# ================= IN-MEM SENSOR STORAGE =================
latest_sensor_data = {"temperature": None, "humidity": None, "soil": None}

# ================= HOME =================
@app.route('/')
def home():
    return "✅ ECC + (toy) Homomorphic metadata API alive!"

# ================= ESP32 → RENDER: update sensor data =================
@app.route('/update', methods=['POST'])
def update_data():
    try:
        data = request.get_json(force=True)
        latest_sensor_data["temperature"] = data.get("temperature")
        latest_sensor_data["humidity"] = data.get("humidity")
        latest_sensor_data["soil"] = data.get("soil")
        return jsonify({"status": "✅ Data updated", "data": latest_sensor_data})
    except Exception as e:
        return jsonify({"error": f"❌ Sensor Update Failed: {e}"}), 400

# ================= MIT AI2 → RENDER: read sensor data =================
@app.route('/get', methods=['GET'])
def get_data():
    if latest_sensor_data["temperature"] is None and \
       latest_sensor_data["humidity"] is None and \
       latest_sensor_data["soil"] is None:
        return jsonify({"error": "❌ No data sent from ESP32, check connection"})
    return jsonify(latest_sensor_data)

# ================= ENCRYPT (ECC + homo metadata) =================
@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    """
    Request JSON (from MIT App Inventor):
      { "value": "<the EXACT text you're showing in your textbox>" }

    Response JSON (for 4 textboxes):
      {
        "homo_id": "<uuid>",
        "ciphertext": "<base64 ECC ciphertext>",
        "key_id": "<uuid for S3 entry>",
        "public_key": "<ECC public key hex>"
      }
    """
    try:
        data = request.get_json(force=True)
        if not data or "value" not in data:
            return jsonify({"error": "Invalid JSON: missing 'value'"}), 400

        value = str(data["value"])  # plaintext from your textbox

        # ECC keypair
        sk = PrivateKey()  # generates a new private key
        sk_hex = sk.to_hex()
        pk_hex = sk.public_key.to_hex(True)  # compressed hex

        # ECC encrypt
        cipher_bytes = encrypt(pk_hex, value.encode())
        ecc_b64 = base64.b64encode(cipher_bytes).decode()

        # “Homomorphic” metadata (toy): just generate an ID to show in textbox
        homo_id = str(uuid.uuid4())

        # Store private key in S3 for later retrieval by key_id
        key_id = str(uuid.uuid4())
        try:
            s3.put_object(
                Bucket=S3_BUCKET,
                Key=f"{key_id}.json",
                Body=json.dumps({"private_key": sk_hex}),
                ContentType='application/json'
            )
        except Exception as s3_err:
            # We still return encryption results even if S3 write failed
            app.logger.error(f"S3 put_object failed: {s3_err}")

        # Return exactly the 4 fields you asked for
        return jsonify({
            "homo_id": homo_id,
            "ciphertext": ecc_b64,
            "key_id": key_id,
            "public_key": pk_hex
        })
    except Exception as e:
        app.logger.exception("Encryption Failed")
        return jsonify({"error": f"❌ Encryption Failed: {e}"}), 500

# ================= Retrieve private key later by key_id =================
@app.route('/get_private_key/<key_id>', methods=['GET'])
def get_private_key(key_id):
    try:
        resp = s3.get_object(Bucket=S3_BUCKET, Key=f"{key_id}.json")
        content = json.loads(resp['Body'].read().decode())
        return jsonify({'private_key': content['private_key']})
    except Exception as e:
        return jsonify({'error': f'❌ Key not found or S3 error: {e}'}), 404

# ================= Decrypt ECC with private key =================
@app.route('/decrypt_with_private_key', methods=['POST'])
def decrypt_with_private_key():
    """
    Request:
      {
        "ecc_encrypted_value": "<base64 ciphertext>",
        "private_key": "<hex>"
      }
    Response:
      { "decrypted_value": "<plaintext>" }
    """
    try:
        data = request.get_json(force=True)
        enc_b64 = data.get('ecc_encrypted_value', '')
        priv_hex = (data.get('private_key', '') or '').strip()

        if not enc_b64 or not priv_hex:
            return jsonify({'error': "Missing fields 'ecc_encrypted_value' or 'private_key'"}), 400

        # Some users paste odd-length hex; left-pad if needed
        if len(priv_hex) % 2 != 0:
            priv_hex = priv_hex.zfill(len(priv_hex) + 1)

        encrypted_bytes = base64.b64decode(enc_b64)
        plain_bytes = decrypt(priv_hex, encrypted_bytes)
        return jsonify({'decrypted_value': plain_bytes.decode()})
    except Exception as e:
        app.logger.exception("ECC Decryption failed")
        return jsonify({'error': f'❌ ECC Decryption failed: {e}'}), 400

# ================= Render entry =================
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)

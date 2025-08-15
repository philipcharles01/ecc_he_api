# app.py
from flask import Flask, request, jsonify
import boto3, uuid, os, base64, json, random
from ecies.utils import generate_key
from ecies import encrypt, decrypt

app = Flask(__name__)
app.config['DEBUG'] = True

# ---------- Configuration (set these in Render environment) ----------
S3_BUCKET = os.getenv('S3_BUCKET', 'ecc-key-store-123')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')

s3 = boto3.client(
    's3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=AWS_REGION
)

# ---------- In-memory sensor storage (for MIT App Inventor) ----------
latest_sensor_data = {"temperature": None, "humidity": None, "soil": None}

# ---------- Logging helper ----------
@app.before_request
def log_request():
    app.logger.debug(f"--- Request to {request.path} ---")
    app.logger.debug(f"Headers: {dict(request.headers)}")
    raw = request.get_data().decode(errors='ignore')
    app.logger.debug(f"Raw body: {raw}")

# ---------- Root ----------
@app.route('/')
def home():
    return "✅ ECC + Homomorphic (toy) API running"

# ---------- ESP32: update sensor data ----------
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
        return jsonify({"error": f"Sensor Update Failed: {e}"}), 400

# ---------- MIT App Inventor: get sensor data ----------
@app.route('/get', methods=['GET'])
def get_data():
    if latest_sensor_data["temperature"] is None and \
       latest_sensor_data["humidity"] is None and \
       latest_sensor_data["soil"] is None:
        return jsonify({"error": "No data sent from ESP32, check connection"})
    return jsonify(latest_sensor_data)

# ---------- ENCRYPT BOTH (ECC + Homomorphic toy) ----------
@app.route('/encrypt_both', methods=['POST'])
def encrypt_both():
    """
    Request JSON:
      { "value": "<plaintext from TextBox>" }

    Response JSON (includes these keys for MIT App Inventor):
      {
        "homo_id": "<uuid>",
        "ciphertext": "<base64 ECC ciphertext>",
        "key_id": "<uuid>",
        "public_key": "<ECC public key hex>",
        # extras:
        "homo_key": <int>,
        "encrypted_value": "<homo-format or numeric>"
      }
    """
    try:
        data = request.get_json(force=True)
        if not data or "value" not in data:
            return jsonify({"error": "Missing 'value' in request JSON"}), 400

        raw_value = str(data["value"])

        # Normalize CR and escape newline characters so stored plaintext is JSON-safe
        safe_for_encrypt = raw_value.replace('\r', '').replace('\n', '\\n')

        # -- ECC key generation (correct) --
        sk = generate_key()               # PrivateKey object
        sk_hex = sk.to_hex()              # private key hex for storage
        pk_bytes = sk.public_key.format(True)  # compressed public key bytes
        pk_hex = pk_bytes.hex()           # hex string to return to client

        # -- ECC encryption: use public key bytes (encrypt expects bytes) --
        cipher_bytes = encrypt(pk_bytes, safe_for_encrypt.encode())
        ciphertext_b64 = base64.b64encode(cipher_bytes).decode()

        # -- Homomorphic (toy) encryption --
        homo_key = random.randint(1, 100)
        try:
            # if plaintext numeric, produce numeric encrypted_value
            encrypted_value = float(raw_value) + homo_key
        except Exception:
            # otherwise store base64-of-plaintext + ::KEY::homo_key
            encrypted_value = base64.b64encode(raw_value.encode()).decode() + "::KEY::" + str(homo_key)

        homo_id = str(uuid.uuid4())

        # -- Store private key in S3 under key_id --
        key_id = str(uuid.uuid4())
        s3_payload = json.dumps({"private_key": sk_hex})
        try:
            s3.put_object(Bucket=S3_BUCKET, Key=f"{key_id}.json",
                          Body=s3_payload, ContentType='application/json')
        except Exception as e:
            # Log but continue returning encryption results
            app.logger.exception(f"S3 put_object failed for key_id {key_id}: {e}")

        # Return the fields App Inventor expects
        return jsonify({
            "homo_id": homo_id,
            "homo_key": homo_key,
            "encrypted_value": encrypted_value,
            "ciphertext": ciphertext_b64,
            "ecc_encrypted_value": ciphertext_b64,
            "key_id": key_id,
            "public_key": pk_hex
        })

    except Exception as e:
        app.logger.exception("encrypt_both failed")
        return jsonify({"error": f"encrypt_both failed: {e}"}), 500

# ---------- Retrieve private key from S3 ----------
@app.route('/get_private_key/<key_id>', methods=['GET'])
def get_private_key(key_id):
    try:
        resp = s3.get_object(Bucket=S3_BUCKET, Key=f"{key_id}.json")
        content = json.loads(resp['Body'].read().decode())
        return jsonify({"private_key": content.get("private_key")})
    except Exception as e:
        app.logger.exception("get_private_key failed")
        return jsonify({"error": f"Key not found or S3 error: {e}"}), 404

# ---------- ECC Decrypt with provided private key ----------
@app.route('/decrypt_with_private_key', methods=['POST'])
def decrypt_with_private_key():
    try:
        data = request.get_json(force=True)
        enc_b64 = data.get('ecc_encrypted_value') or data.get('ciphertext') or ''
        private_key_hex = (data.get('private_key', '') or '').strip()

        if not enc_b64 or not private_key_hex:
            return jsonify({"error": "Missing 'ecc_encrypted_value' (or 'ciphertext') or 'private_key'"}), 400

        encrypted_bytes = base64.b64decode(enc_b64)

        # Try decrypt with hex string first; if fails, try bytes.fromhex
        try:
            plain_bytes = decrypt(private_key_hex, encrypted_bytes)
        except Exception:
            plain_bytes = decrypt(bytes.fromhex(private_key_hex), encrypted_bytes)

        plaintext = plain_bytes.decode()
        # restore newline escapes
        plaintext = plaintext.replace('\\n', '\n')
        return jsonify({"decrypted_value": plaintext})
    except Exception as e:
        app.logger.exception("decrypt_with_private_key failed")
        return jsonify({"error": f"ECC decryption failed: {e}"}), 400

# ---------- Homomorphic decrypt (toy) ----------
@app.route('/decrypt', methods=['POST'])
def decrypt_homomorphic():
    try:
        data = request.get_json(force=True)
        encrypted_value = data.get('encrypted_value')
        homo_key = data.get('homo_key')

        if encrypted_value is None or homo_key is None:
            return jsonify({"error": "Missing 'encrypted_value' or 'homo_key'"}), 400

        # numeric case
        try:
            val = float(encrypted_value)
            plain = val - int(homo_key)
            return jsonify({"decrypted_value": plain})
        except Exception:
            # string case: maybe "<b64>::KEY::<k>" or just base64
            try:
                b64part = str(encrypted_value).split("::KEY::")[0]
                plain_bytes = base64.b64decode(b64part)
                return jsonify({"decrypted_value": plain_bytes.decode()})
            except Exception as e:
                return jsonify({"error": f"Cannot decode homomorphic value: {e}"}), 400

    except Exception as e:
        app.logger.exception("decrypt (homomorphic) failed")
        return jsonify({"error": f"Homomorphic decryption failed: {e}"}), 400

# ---------- Run ----------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)

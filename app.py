from flask import Flask, request, jsonify
import boto3, uuid, os, base64, json, random
from ecies.utils import generate_key
from ecies import encrypt, decrypt

app = Flask(__name__)
app.config['DEBUG'] = True

# ====== Configuration (set these in Render environment) ======
S3_BUCKET = os.getenv('S3_BUCKET', 'ecc-key-store-123')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')

s3 = boto3.client(
    's3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=AWS_REGION
)

# ====== In-memory sensor store (for MIT App Inventor GET) ======
latest_sensor_data = {"temperature": None, "humidity": None, "soil": None}

# ====== Logging helper (keep raw body for debugging) ======
@app.before_request
def log_request():
    app.logger.debug(f"--- Request to {request.path} ---")
    app.logger.debug(f"Headers: {dict(request.headers)}")
    raw = request.get_data().decode(errors='ignore')
    app.logger.debug(f"Raw body: {raw}")

# ====== Home ======
@app.route('/')
def home():
    return "✅ ECC + Homomorphic API (with S3 key storage) is running."

# ====== ENCRYPT endpoint ======
@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    """
    Request JSON:
      { "value": "<plaintext — can be multiline>" }

    Response JSON:
      {
        "homo_id": "<uuid>",
        "homo_key": <int>,
        "encrypted_value": "<homo-format OR numeric>",
        "ciphertext": "<ecc ciphertext base64>",
        "ecc_encrypted_value": "<same as ciphertext>",
        "key_id": "<uuid>",
        "public_key": "<ecc public key hex>"
      }
    """
    try:
        data = request.get_json(force=True)
        if not data or "value" not in data:
            return jsonify({"error": "Missing 'value' in JSON"}), 400

        # plaintext from client (TextBox content). Normalize newlines:
        raw_value = str(data["value"])
        # Replace CRs and keep newlines escaped so S3 and JSON transport are safe:
        safe_value = raw_value.replace('\r', '').replace('\n', '\\n')

        # --- ECC keypair generation (correct method) ---
        sk = generate_key()            # returns a PrivateKey
        sk_hex = sk.to_hex()           # private key hex (store this)
        pk_bytes = sk.public_key.format(True)  # compressed public key bytes
        pk_hex = pk_bytes.hex()        # hex string for returning

        # --- ECC encryption ---
        cipher_bytes = encrypt(pk_bytes, safe_value.encode())  # encrypt expects bytes
        ciphertext_b64 = base64.b64encode(cipher_bytes).decode()

        # --- Homomorphic-style (toy) encryption ---
        homo_key = random.randint(1, 100)
        try:
            # if plaintext looks like a number, produce numeric encrypted_value
            encrypted_value = float(raw_value) + homo_key
        except Exception:
            # otherwise create a safe payload containing base64 plaintext + key id
            encrypted_value = base64.b64encode(raw_value.encode()).decode() + "::KEY::" + str(homo_key)

        homo_id = str(uuid.uuid4())

        # --- Store private key in S3 (store hex string in a small JSON file) ---
        key_id = str(uuid.uuid4())
        s3_body = json.dumps({"private_key": sk_hex})
        try:
            s3.put_object(Bucket=S3_BUCKET, Key=f"{key_id}.json",
                          Body=s3_body, ContentType='application/json')
        except Exception as e:
            # log error but still return encryption results (caller can retry S3)
            app.logger.exception("S3 put_object failed")

        # --- Return results ---
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
        app.logger.exception("Encryption failed")
        return jsonify({"error": f"Encryption failed: {e}"}), 500

# ====== GET PRIVATE KEY (from S3) ======
@app.route('/get_private_key/<key_id>', methods=['GET'])
def get_private_key(key_id):
    try:
        resp = s3.get_object(Bucket=S3_BUCKET, Key=f"{key_id}.json")
        content = json.loads(resp['Body'].read().decode())
        return jsonify({"private_key": content["private_key"]})
    except Exception as e:
        app.logger.exception("Get private key failed")
        return jsonify({"error": f"Key not found or S3 error: {e}"}), 404

# ====== ECC DECRYPT WITH PROVIDED PRIVATE KEY ======
@app.route('/decrypt_with_private_key', methods=['POST'])
def decrypt_with_private_key():
    """
    Request:
      {
        "ecc_encrypted_value": "<base64 ciphertext>",
        "private_key": "<hex private key>"
      }
    Response:
      { "decrypted_value": "<plaintext>" }
    """
    try:
        data = request.get_json(force=True)
        enc_b64 = data.get('ecc_encrypted_value', '')
        private_key_hex = (data.get('private_key', '') or '').strip()

        if not enc_b64 or not private_key_hex:
            return jsonify({"error": "Missing 'ecc_encrypted_value' or 'private_key'"}), 400

        # base64 -> bytes
        encrypted_bytes = base64.b64decode(enc_b64)

        # Try decrypt using hex string, but ecies.decrypt accepts several forms,
        # handle both: try hex string, and if that fails try bytes.fromhex
        try:
            plain_bytes = decrypt(private_key_hex, encrypted_bytes)
        except Exception:
            # try with bytes
            plain_bytes = decrypt(bytes.fromhex(private_key_hex), encrypted_bytes)

        plaintext = plain_bytes.decode()
        # restore newline escapes if needed (we stored newlines as \\n)
        plaintext = plaintext.replace('\\n', '\n')
        return jsonify({"decrypted_value": plaintext})
    except Exception as e:
        app.logger.exception("ECC Decryption failed")
        return jsonify({"error": f"ECC Decryption failed: {e}"}), 400

# ====== HOMOMORPHIC DECRYPT (toy) ======
@app.route('/decrypt', methods=['POST'])
def decrypt_homomorphic():
    try:
        data = request.get_json(force=True)
        encrypted_value = data.get('encrypted_value', None)
        homo_key = data.get('homo_key', None)
        if encrypted_value is None or homo_key is None:
            return jsonify({"error": "Missing 'encrypted_value' or 'homo_key'"}), 400

        # if encrypted_value is numeric (sent as number), just subtract
        try:
            val = float(encrypted_value)
            plain = val - int(homo_key)
            return jsonify({"decrypted_value": plain})
        except Exception:
            # otherwise assume format base64::KEY::homo_key
            # But we already have homo_key, so decode base64 part
            try:
                # if encrypted_value is like "<b64>::KEY::<k>"
                b64part = str(encrypted_value).split("::KEY::")[0]
                plain_bytes = base64.b64decode(b64part)
                return jsonify({"decrypted_value": plain_bytes.decode()})
            except Exception as e:
                return jsonify({"error": f"Cannot decode homomorphic value: {e}"}), 400

    except Exception as e:
        app.logger.exception("Homomorphic decryption failed")
        return jsonify({"error": f"Homomorphic decryption failed: {e}"}), 400

# ====== ESP32: Update sensor data ======
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
        return jsonify({"status": "Data updated", "data": latest_sensor_data})
    except Exception as e:
        app.logger.exception("Sensor update failed")
        return jsonify({"error": f"Sensor update failed: {e}"}), 400

# ====== MIT APP INVENTOR: GET sensor data (with no-data message) ======
@app.route('/get', methods=['GET'])
def get_data():
    if latest_sensor_data["temperature"] is None and \
       latest_sensor_data["humidity"] is None and \
       latest_sensor_data["soil"] is None:
        return jsonify({"error": "No data sent from ESP32, check connection"})
    return jsonify(latest_sensor_data)

# ====== Run ======
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)

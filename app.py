from flask import Flask, request, jsonify
from tinyec import registry
import secrets

app = Flask(__name__)

# ECC encryption
curve = registry.get_curve('brainpoolP256r1')

def ecc_keygen():
    private_key = secrets.randbelow(curve.field.n)
    public_key = private_key * curve.g
    return private_key, public_key

@app.route("/", methods=["GET"])
def home():
    return "Flask ECC + HE API is working!"

@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.json.get("data", "")
    
    # ECC Key Generation
    priv_key, pub_key = ecc_keygen()
    pub = {'x': pub_key.x, 'y': pub_key.y}
    
    # Fake Homomorphic encryption (demo purpose)
    encrypted_data = ''.join([chr(ord(char) + 1) for char in data])

    return jsonify({
        "original": data,
        "encrypted": encrypted_data,
        "ecc_public_key": pub,
        "ecc_private_key": priv_key
    })

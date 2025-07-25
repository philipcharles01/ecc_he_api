from flask import Flask, jsonify
from Crypto.PublicKey import ECC
from phe import paillier

app = Flask(__name__)

@app.route('/')
def home():
    return "ECC + Homomorphic Encryption API"

@app.route('/generate_keys')
def generate_keys():
    ecc_key = ECC.generate(curve='P-256')
    ecc_private = ecc_key.export_key(format='PEM')
    ecc_public = ecc_key.public_key().export_key(format='PEM')

    public_key, private_key = paillier.generate_paillier_keypair()

    return jsonify({
        "ecc_public": ecc_public,
        "ecc_private": ecc_private,
        "he_public": {
            "n": str(public_key.n)
        },
        "he_private": {
            "p": str(private_key.p),
            "q": str(private_key.q)
        }
    })

if __name__ == '__main__':
    app.run()

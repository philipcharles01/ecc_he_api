from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Flask ECC + HE API is working!"

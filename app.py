from flask import flask

app = Flask(_name_)

@app.route("/")
def home():
	return "Flask ECC + HE API is working"

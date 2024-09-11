#!/usr/bin/env python3
'''Basic Flask app'''
from auth import Auth
from flask import Flask, jsonify, request


app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    '''return the home page'''
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def users() -> str:
    '''register a new user'''
    email = request.form.get("email")
    password = request.form.get("password")
    if not email or not password:
        return jsonify({"message": "email and password are required"}), 400
    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"}), 201
    except ValueError:
        return jsonify({"message": "email already registeres"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")

from flask import Flask, request
import json
from src.hmac_helper import HMACHelper
import mock_data

app = Flask(__name__)


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


@app.post("/signed-endpoint-OneKeyHMAC")
def signed_endpoint_one_key_HMAC():
    client_hmac = request.headers.get("Authorization")

    message_bytes = request.data
    hmac = HMACHelper(mock_data.PRIVATE_KEY)

    if hmac.validate_request(client_hmac, message_bytes):
        return "Success", 200
    return "Access Denied", 401


@app.post("/signed-endpoint-TwoKeyHMAC")
def signed_endpoint_two_key_HMAC():
    """First parse the public key from the request body
    Then get the private key from the database
    and validate it matches the private key from the request HMAC
    """
    client_hmac = request.headers.get("Authorization")

    message_json = request.get_json()
    message: dict = json.load(message_json)
    public_key = message.get("public_key")

    # query database for private key
    private_key = mock_data.db.get(public_key)
    if not private_key:
        return "Access Denied", 401

    hmac = HMACHelper(private_key)
    if hmac.validate_request(client_hmac, message=request.data):
        return "Success", 200
    return "Access Denied", 401

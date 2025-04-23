import requests
import json
from hashlib import sha256
import hmac
import secrets


class HMACHelper:
    """HMAC is symetric one key auth where both parties have the same private key."""

    def __init__(self, private_key: bytes = None):

        if not private_key:
            self.private_key = secrets.token_bytes(16)  # keys should be 128 bits
        else:
            self.private_key = private_key
            assert isinstance(
                private_key, bytes
            ), "Private key must be bytes and should be generated using secrets.token_bytes(16)"

    def _create_hmac(self, message: str) -> str:
        """Create HMAC by hashing the private key and message."""

        assert isinstance(message, (str, bytes)), "Message must be a string or bytes"

        if isinstance(message, str):
            message = message.encode("utf-8")

        return hmac.new(self.private_key, message, sha256).hexdigest()

    def send_request(self, url, message: str | dict):
        """For use on the client to include hashed value in the request."""

        if isinstance(message, dict):
            message = json.dumps(message)

        # Pass the hashed message + private key in the header
        headers = {
            "content-type": "application/json",
            "Authorization": self._create_hmac(message),
        }
        return requests.post(url=url, data=message, headers=headers)

    def validate_request(self, client_hmac: str, message: str | bytes) -> bool:
        """For use on the server to validate if the message has been sent with the same private key."""
        server_hmac = self._create_hmac(message=message)
        assert type(server_hmac) == type(client_hmac)
        return hmac.compare_digest(server_hmac, client_hmac)

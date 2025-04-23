from src.hmac_helper import HMACHelper
import mock_data
import base64


def one_key_HMAC():
    """Send a message to a server that has the same private key"""

    url = "http://127.0.0.1:5000/signed-endpoint-OneKeyHMAC"
    message = {"name": "Sam"}

    oka = HMACHelper(mock_data.PRIVATE_KEY)
    return oka.send_request(url, message)


def two_key_HMAC():
    """Public key should be included in the message.
    first encode bytes to base64 then into a utf-8 string so that it can be json parsed.
    """

    url = "http://127.0.0.1:5000/signed-endpoint-OneKeyHMAC"
    # data includes public key and potentially timestamp.
    message = {
        "public_key": base64.b64encode(mock_data.CLIENT_1_PUBLIC_KEY).decode("utf-8"),
        "name": "Sam",
    }

    oka = HMACHelper(mock_data.PRIVATE_KEY)
    return oka.send_request(url, message)


if __name__ == "__main__":
    print(one_key_HMAC())
    print(two_key_HMAC())

# Minimal Implementation of secure API endpoints with HMAC
## One Key HMAC:
Client request sends a message body and a header containing the hash of the body + private key.

The server then re-hashes the body with its private key and compares it to the hash sent in the header.

## Two Key HMAC:
Client has a private key and a public key

Client request sends the message body with the public key and the header containing the hash of the body + private key

The server then extracts the public key from the message body and looks up the matching private key.

This is then re-hashed along with the complete message body and compared to the hash sent in the header.

## Further Additions:
Timestamps or 'nonces' can also be sent within the message body which can be used to deny stale requests.

The use of a nonce stops replay attacks.

## HMAC Keys
Private keys should be at least 128 bits in length and generated securely

They can either be passed offline or by wrapping with RSA keys

Public keys can be linked to an individual application or to a version

# Scripts
flask --app server run

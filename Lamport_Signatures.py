import hashlib
import secrets

def hash(data):
    """Returns the SHA-256 hash of the given data."""
    return hashlib.sha256(data).digest()

def generate_keypair():
    """Generates a Lamport signature keypair."""
    private_key = []
    public_key = []

    for _ in range(256):
        sk0 = secrets.randbits(256)
        sk1 = secrets.randbits(256)
        pk0 = hash(sk0.to_bytes(32, 'big'))
        pk1 = hash(sk1.to_bytes(32, 'big'))

        private_key.append((sk0, sk1))
        public_key.append((pk0, pk1))

    return private_key, public_key

def sign(message, private_key):
    """Generates a Lamport signature for the given message using the private key."""
    message_hash = hash(message)
    signature = []

    for i in range(256):
        bit = (message_hash[i // 8] >> (7 - (i % 8))) & 1
        signature.append(private_key[i][bit])

    return signature

def verify(message, signature, public_key):
    """Verifies a Lamport signature for the given message using the public key."""
    message_hash = hash(message)

    for i in range(256):
        bit = (message_hash[i // 8] >> (7 - (i % 8))) & 1
        expected_pk = public_key[i][bit]
        actual_pk = hash(signature[i].to_bytes(32, 'big'))

        if expected_pk != actual_pk:
            return False

    return True

private_key, public_key = generate_keypair()
msg = b"Message for testing Lamport signatures."
signature = sign(msg, private_key)

assert verify(msg, signature, public_key), "Signature verification failed!"
print("Signature verified successfully!")
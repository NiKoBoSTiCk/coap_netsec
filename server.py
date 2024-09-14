import aiocoap
import aiocoap.resource as resource
import asyncio
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

# Security parameters
SECURITY_LEVEL = 2  # Defines the security level (1 = confidentiality, 2 = integrity, 3 = authentication)
# Encryption constants
NONCE_LENGTH = 11  # Nonce length for AES-CCM (used for encryption with integrity)
TAG_LENGTH = 16  # Tag length for AES-CCM (used for integrity verification)
IV_LENGTH = 16  # Initialization Vector length for AES-CBC (used for encryption without integrity)
KEY_LENGTH = 16  # AES key length (128 bits)
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2  # Generator for Diffie-Hellman (DH) key exchange


class ControlResource(resource.Resource):
    def __init__(self):
        super().__init__()

    async def render_put(self, request):
        """
        Handles PUT requests to change the security level.
        """
        global SECURITY_LEVEL
        level = int(request.payload)
        assert level in [1, 2, 3]  # Security level must be 1, 2, or 3
        SECURITY_LEVEL = level
        print(f"SECURITY LEVEL SET TO: {SECURITY_LEVEL}")
        return aiocoap.Message(payload=b'SECURITY LEVEL CHANGED')

    async def render_get(self, request):
        """
        Handles GET requests to retrieve the current security level.
        """
        global SECURITY_LEVEL
        assert SECURITY_LEVEL in [1, 2, 3]
        return aiocoap.Message(payload=str(SECURITY_LEVEL).encode())


class SecureResource(resource.Resource):

    def __init__(self):
        super().__init__()
        print(f"SECURITY LEVEL IS {SECURITY_LEVEL}")
        print("GENERATING RSA KEY....")
        self.rsa_private_key = RSA.generate(2048)  # Generate RSA private key
        print("GENERATING DIFFIE-HELLMAN KEY....")
        params_numbers = dh.DHParameterNumbers(p, g)  # Diffie-Hellman parameters
        parameters = params_numbers.parameters(default_backend())
        self.dh_private_key = parameters.generate_private_key()  # DH private key
        self.shared_key = None  # Shared key after key exchange
        print("INIT COMPLETED")

    async def render_get(self, request):
        """
        Handles GET requests to provide the public key (RSA or DH).
        """
        if SECURITY_LEVEL == 3:
            # Returns the DH public key in DER format if security level is 3 (authentication)
            dh_public_key = self.dh_private_key.public_key().public_bytes(
                encoding=Encoding.DER,
                format=PublicFormat.SubjectPublicKeyInfo
            )
            return aiocoap.Message(payload=dh_public_key)
        else:
            # Returns the RSA public key in PEM format for security levels 1 and 2
            rsa_public_key = self.rsa_private_key.public_key().export_key()
            return aiocoap.Message(payload=rsa_public_key)

    async def render_put(self, request):
        """
        Handles the key exchange and computes the shared key based on the security level.
        """
        try:
            if SECURITY_LEVEL == 3:
                # Handles Diffie-Hellman key exchange for security level 3
                print("HANDLING DIFFIE-HELLMAN KEY EXCHANGE....")
                client_public_key = request.payload
                shared_secret = self.dh_private_key.exchange(load_der_public_key(client_public_key))
                self.shared_key = SHA256.new(shared_secret).digest()[:KEY_LENGTH]  # Derive shared key using SHA-256
                print("KEY EXCHANGE COMPLETED")
                return aiocoap.Message()

            else:
                # Handles RSA key exchange for security levels 1 and 2
                print("HANDLING RSA KEY EXCHANGE....")
                rsa_cipher = PKCS1_OAEP.new(self.rsa_private_key)
                shared_secret = rsa_cipher.decrypt(request.payload)  # Decrypt shared secret
                self.shared_key = SHA256.new(shared_secret).digest()[:KEY_LENGTH]  # Derive shared key using SHA-256
                print("KEY EXCHANGE COMPLETED")
                return aiocoap.Message()
        except (ValueError, KeyError, TypeError):
            # If the key exchange fails, return a BAD REQUEST response
            print("KEY EXCHANGE FAILED")
            return aiocoap.Message(code=aiocoap.Code.BAD_REQUEST)

    async def render_post(self, request):
        """
        Handles encrypted messages sent by the client and decrypts them.
        """
        print("MESSAGE RECEIVED, DECRYPTING...")
        payload = request.payload

        try:
            if SECURITY_LEVEL > 1:
                # Decrypt message using AES-CCM (confidentiality and integrity)
                nonce = payload[:NONCE_LENGTH]
                tag = payload[NONCE_LENGTH:NONCE_LENGTH + TAG_LENGTH]
                ciphertext = payload[NONCE_LENGTH + TAG_LENGTH:]
                plaintext = aes_integrity_decrypt(nonce, tag, ciphertext, self.shared_key)
            else:
                # Decrypt message using AES-CBC (confidentiality only)
                iv = payload[:IV_LENGTH]
                ciphertext = payload[IV_LENGTH:]
                plaintext = aes_decrypt(iv, ciphertext, self.shared_key)

            print(f'RECEIVED MESSAGE: {plaintext.decode("utf-8")}')
            return aiocoap.Message(payload=plaintext)
        except (ValueError, KeyError, TypeError):
            # If decryption fails, return a BAD REQUEST response
            print("DECRYPTION FAILED")
            return aiocoap.Message(code=aiocoap.Code.BAD_REQUEST)


# Utility functions for AES encryption and decryption
def aes_encrypt(plaintext, key):
    """
    Encrypts a message using AES in CBC mode (confidentiality only).

    :param plaintext: The message to encrypt.
    :param key: The AES cryptographic key.
    :return: iv, ciphertext: The Initialization Vector and encrypted message.
    """
    verify_key(key)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return cipher.iv, ciphertext


def aes_decrypt(iv, ciphertext, key):
    """
    Decrypts a message encrypted with AES in CBC mode.

    :param iv: The Initialization Vector.
    :param ciphertext: The encrypted message.
    :param key: The AES cryptographic key.
    :return: The decrypted message.
    """
    verify_key(key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext


def aes_integrity_encrypt(plaintext, key):
    """
    Encrypts a message using AES in CCM mode (confidentiality and integrity).

    :param plaintext: The message to encrypt.
    :param key: The AES cryptographic key.
    :return: nonce, tag, ciphertext: The nonce, integrity tag, and encrypted message.
    """
    verify_key(key)
    cipher = AES.new(key, AES.MODE_CCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, tag, ciphertext


def aes_integrity_decrypt(nonce, tag, ciphertext, key):
    """
    Decrypts a message encrypted with AES in CCM mode.

    :param nonce: The nonce used for encryption.
    :param tag: The integrity tag.
    :param ciphertext: The encrypted message.
    :param key: The AES cryptographic key.
    :return: The decrypted message.
    """
    verify_key(key)
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def verify_key(key):
    """
    Verifies that the provided AES key has the correct length.
    """
    assert len(key) == AES.block_size


# Function to start the CoAP server
def start_coap_server():
    """
    Creates and starts the CoAP server with the specified resources.
    """
    root = resource.Site()
    root.add_resource(['secure'], SecureResource())  # Secure resource for encryption
    root.add_resource(['security_level'], ControlResource())  # Resource to control security level
    asyncio.Task(aiocoap.Context.create_server_context(root))  # Start the CoAP server context
    asyncio.get_event_loop().run_forever()  # Run the server indefinitely


# Main function to start the server
def main():
    """
    Main function to start the CoAP server.
    """
    start_coap_server()


if __name__ == "__main__":
    main()

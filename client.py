import aiocoap
import asyncio
from asyncio import sleep
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

# Network parameters
SERVER_IP = 'localhost'
SERVER_PORT = 5683

# Constants for encryption
KEY_LENGTH = 16  # AES key length in bytes
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2


class CoAPClient:
    def __init__(self):
        super().__init__()
        self.protocol = None
        self.shared_key = None  # Shared key derived from RSA/DH key exchange
        self.security_level = None  # Security level retrieved from server

    async def run(self):
        """
        Main function to start the client:
        - Creates the CoAP client context
        - Requests the security level from the server
        - Handles the key exchange based on the security level
        - Loops to allow sending interactive messages
        """
        self.protocol = await aiocoap.Context.create_client_context()  # Initializes CoAP client
        await self._request_security_level()  # Retrieves security level from the server
        await self._handle_key_exchange()  # Executes the appropriate key exchange (DH or RSA)

        # Main loop for sending messages interactively
        while True:
            message = input("Enter the message to send (or 'restart' to restart): ")
            if message.lower() == 'restart':
                await self._request_security_level()  # Re-fetch security level from the server
                await self._handle_key_exchange()  # Perform key exchange again
            else:
                await self._send_message(message)  # Send the input message
                await sleep(2)  # Wait before allowing another input

    async def _request_security_level(self):
        """
        Sends a GET request to retrieve the security level from the server.
        The level should be 1 (Confidentiality), 2 (Integrity), or 3 (Authentication).
        """
        request = aiocoap.Message(
            code=aiocoap.Code.GET,
            uri=f'coap://{SERVER_IP}:{SERVER_PORT}/security_level'
        )
        response = await self.protocol.request(request).response  # Wait for the server response
        self.security_level = int(response.payload)  # Convert the received payload to an integer
        assert self.security_level in [1, 2, 3]  # Ensure valid security level
        print(f"Security level: {self.security_level}")

    async def _handle_key_exchange(self):
        """
        Performs key exchange based on the security level:
        - Level 1: Confidentiality only (AES encryption)
        - Level 2: Confidentiality and Integrity (AES encryption with integrity check)
        - Level 3: Authentication (Diffie-Hellman key exchange for shared key derivation)
        """
        print("Fetching the server's public key...")

        # Send GET request to fetch the server's public key
        request = aiocoap.Message(
            code=aiocoap.Code.GET,
            uri=f'coap://{SERVER_IP}:{SERVER_PORT}/secure'
        )
        response = await self.protocol.request(request).response  # Server's public key as response payload
        server_public_key = response.payload

        if self.security_level == 3:
            # Diffie-Hellman key exchange for authentication
            print("Handling Diffie-Hellman key exchange...")
            params_numbers = dh.DHParameterNumbers(p, g)  # Initialize DH parameters with prime p and generator g
            parameters = params_numbers.parameters(default_backend())
            private_key = parameters.generate_private_key()  # Generate client's private key

            # Generate shared secret using server's public key and derive AES key
            shared_secret = private_key.exchange(load_der_public_key(server_public_key))
            self.shared_key = SHA256.new(shared_secret).digest()[:KEY_LENGTH]  # Truncate key to required length

            # Send client's public key to the server
            payload = private_key.public_key().public_bytes(
                encoding=Encoding.DER,
                format=PublicFormat.SubjectPublicKeyInfo
            )
            print("Key exchange completed.")
            request = aiocoap.Message(
                code=aiocoap.Code.PUT,
                uri=f'coap://{SERVER_IP}:{SERVER_PORT}/secure',
                payload=payload
            )
        else:
            # RSA key exchange for confidentiality or integrity
            print("Handling RSA key exchange...")
            shared_secret = get_random_bytes(32)  # Generate a random secret for encryption
            rsa_cipher = PKCS1_OAEP.new(RSA.import_key(server_public_key))  # Initialize RSA cipher
            payload = rsa_cipher.encrypt(shared_secret)  # Encrypt the secret with server's public key
            self.shared_key = SHA256.new(shared_secret).digest()[:KEY_LENGTH]  # Derive AES key from shared secret
            print("Key exchange completed.")
            request = aiocoap.Message(
                code=aiocoap.Code.PUT,
                uri=f'coap://{SERVER_IP}:{SERVER_PORT}/secure',
                payload=payload
            )
        await self.protocol.request(request).response  # Send the PUT request to server

    async def _send_message(self, message):
        """
        Encrypts and sends a message to the server, based on the security level:
        - Level 1: Confidentiality (AES encryption)
        - Level 2: Confidentiality and Integrity (AES with integrity)
        - Level 3: Authentication (DH-based encryption)
        """
        print("Encrypting the message...")

        if self.security_level > 1:
            # AES encryption with integrity (CCM mode)
            nonce, tag, ciphertext = aes_integrity_encrypt(message, self.shared_key)
            print("Sending encrypted message with integrity to server...")
            request = aiocoap.Message(
                code=aiocoap.Code.POST,
                uri=f'coap://{SERVER_IP}:{SERVER_PORT}/secure',
                payload=nonce + tag + ciphertext  # Concatenate nonce, tag, and ciphertext
            )
        else:
            # AES encryption (CBC mode) for confidentiality
            iv, ciphertext = aes_encrypt(message, self.shared_key)
            print("Sending encrypted message to server...")
            request = aiocoap.Message(
                code=aiocoap.Code.POST,
                uri=f'coap://{SERVER_IP}:{SERVER_PORT}/secure',
                payload=iv + ciphertext  # Concatenate IV and ciphertext
            )

        response = await self.protocol.request(request).response  # Wait for server response
        print(f"Server response: {response.payload.decode()}")  # Display server's reply


# Encryption functions
def aes_encrypt(plaintext, key):
    """
    Encrypts the message using AES (CBC mode) for confidentiality.

    :param plaintext: The message to encrypt.
    :param key: The AES encryption key.
    :return: iv, ciphertext: Initialization Vector and encrypted message.
    """
    verify_key(key)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))  # Pad and encrypt message
    return cipher.iv, ciphertext


def aes_integrity_encrypt(plaintext, key):
    """
    Encrypts the message using AES (CCM mode) for confidentiality and integrity.

    :param plaintext: The message to encrypt.
    :param key: The AES encryption key.
    :return: nonce, tag, ciphertext: Nonce, integrity tag, and encrypted message.
    """
    verify_key(key)
    cipher = AES.new(key, AES.MODE_CCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))  # Encrypt and generate tag
    return cipher.nonce, tag, ciphertext


# Helper function to verify key length
def verify_key(key):
    assert len(key) == AES.block_size, "Invalid key length!"  # Ensure key is the correct length


# Main function to start the client
if __name__ == "__main__":
    client = CoAPClient()
    asyncio.get_event_loop().run_until_complete(client.run())

Image Encryption and Decryption Server
An advanced platform designed for secure image processing, utilizing encryption and decryption mechanisms in a client-server architecture. This application ensures image confidentiality during upload, storage, and retrieval, using cutting-edge cryptographic techniques.

Features
End-to-End Encryption: Secure image uploads using AES for encryption and RSA for secure key exchange.
Public/Private Key Management: Generates and manages public/private keys during user registration. The public key is stored on the server, while the private key is downloaded locally.
Authentication & Authorization: Ensures secure user access through JWT or OAuth2 protocols.
Image Integrity Verification: Verifies image authenticity with OTP verification and hash-based integrity checks.
Secure Key Exchange: Encrypts AES keys with RSA before transmission, ensuring only the intended recipient can decrypt.
How It Works
User Registration:

Generates public and private RSA keys.
Public key is stored in the database; the private key is downloaded locally by the user.
Image Upload:

The image is encrypted using AES before being uploaded to the server.
The encryption key is further encrypted using RSA and securely transmitted.
Decryption Process:

Users upload the encrypted image and their private key.
The server decrypts the AES key using the user's private key, then decrypts the image.
Verification:

OTP is sent for an additional layer of security.
Image hashes ensure the file hasn’t been tampered with.



import base64

import firebase_admin
from firebase_admin import credentials,db
import requests
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
import json
import smtplib
import random
import hashlib


cred = credentials.Certificate("cred.json")
firebase_admin.initialize_app(cred, {
    "databaseURL": "https://data-transfer-dc08d-default-rtdb.asia-southeast1.firebasedatabase.app/"
})

# Test initialization
try:
    ref = db.reference('/')
    print("Firebase initialized successfully.")
except Exception as e:
    print(f"Error initializing Firebase: {e}")

#hospital_data = {1:{'name': 'UV mal', 'address': 'Udupi', 'contact_email': 'urmom@gmail.com', 'contact_phone': '99029029302'}}
def register(hospital_data):
    try:
        ref = db.reference(hospital_data['name'])
        ref.set(hospital_data)
        os.makedirs(hospital_data['name'], exist_ok=True)

    except Exception as e:
        raise Exception(f"Failed to register hospital: {str(e)}")


def generateRSA_keys(hospital_data, private_key_file='private_key.pem'):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize the public key
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Encode the public key bytes to a Base64 string
    hospital_data['public_key_bytes'] = base64.b64encode(public_key_bytes).decode('utf-8')

    # Serialize the private key to PEM format and save it to a file
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
        # No password protection (use `BestAvailableEncryption` for password protection)
    )

    with open(private_key_file, 'wb') as file:
        file.write(private_key_bytes)

    print(f"Private key saved to {private_key_file}")

    return hospital_data
def login_hospital(name,password):
    ref = db.reference(name)
    data = ref.get()

    if data['password'] == password:
        message = {'Login': "Successfully logged in"}
        status = True
    else:
        message = {'Login': "Wrong password"}
        status = False
    return message,status

def get_hospitals():
    hospitals = []
    ref = db.reference('/')
    data = ref.get()
    #print(data)
    for doc in data:
        #print(doc)
        temp = {'name' : doc}
        hospitals.append(temp)
    return {"hospitals": hospitals}





def calculate_image_hash(image_path):
    """Calculate the SHA-256 hash of an image."""
    hash_sha256 = hashlib.sha256()

    # Open image file in binary mode
    with open(image_path, "rb") as image_file:
        # Read and update hash in chunks to handle large files
        for chunk in iter(lambda: image_file.read(4096), b""):
            hash_sha256.update(chunk)

    # Return the hash in hexadecimal format
    return hash_sha256.hexdigest()


def encrypt_image_with_aes_and_rsa(image_path: str, hospital: str):
    # Step 1: Read the image from the given path
    hash_value = calculate_image_hash(image_path)
    with open('current_hospital.json', 'r') as json_file:
        # Load the JSON data into a Python object (typically a dictionary)
        data = json.load(json_file)
    sender = data['hospital_name']


    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image file {image_path} does not exist.")

    with open(image_path, "rb") as image_file:
        image_data = image_file.read()

    # Step 2: Generate AES key and IV
    aes_key = os.urandom(32)  # 256-bit key for AES
    iv = os.urandom(16)  # Initialization vector

    # Step 3: Pad the image data for AES encryption
    padder = aes_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(image_data) + padder.finalize()

    # Step 4: Encrypt the image data using AES in CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_image = encryptor.update(padded_data) + encryptor.finalize()

    # Step 5: Retrieve the RSA public key from Firebase
    ref = db.reference(f'/{hospital}')  # assuming this is the path in Firebase
    rsa_pub_key_base64 = ref.get()['public_key_bytes']  # Fetching RSA public key from Firebase (base64 encoded)

    # Step 6: Decode the base64 public key and wrap it in PEM format
    rsa_pub_key_bytes = base64.b64decode(rsa_pub_key_base64)

    # Step 7: Load the RSA public key
    rsa_pub_key = serialization.load_pem_public_key(rsa_pub_key_bytes, backend=default_backend())

    # Step 8: Encrypt the AES key using RSA public key
    encrypted_aes_key = rsa_pub_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 9: Save the encrypted image and AES key to files
    hash_path = f"{hospital}/hash_value_{hospital}.txt"
    encrypted_image_path = f"{hospital}/encrypted_image_{sender}.bin"
    encrypted_key_path = f"{hospital}/encrypted_aes_key_{sender}.bin"

    with open(encrypted_image_path, "wb") as image_file:
        image_file.write(iv + encrypted_image)  # Save IV + encrypted image

    with open(encrypted_key_path, "wb") as key_file:
        key_file.write(encrypted_aes_key)

    with open(hash_path, "w") as hash_file:
        hash_file.write(hash_value)
    # Save encrypted AES key

    print(f"Encrypted image saved at {encrypted_image_path}")
    print(f"Encrypted AES key saved at {encrypted_key_path}")
    print(f"Hash value saved at {hash_path}")


    return encrypted_image_path, encrypted_key_path




def send_otp_via_email():
    # Generate a 6-digit OTP
    otp = random.randint(100000, 999999)

    # Define email server and login credentials
    sender_email = "imageencryptionplaform@gmail.com"
    password = "xugm yskb yakz xarx"
    subject = "Your OTP Code"
    message = f"Your OTP code is {otp}"
    curr_hosp = get_current_hospital()
    hospital_ref = db.reference(f'/{curr_hosp}')
    hosp_data= hospital_ref.get()
    receiver_email = hosp_data['contact_email']

    # Add the OTP field
    hospital_ref.update({"OTP": otp})
    # Connect to Gmail's SMTP server
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Upgrade to secure connection
        server.login(sender_email, password)

        # Send the email
        email_message = f"Subject: {subject}\n\n{message}"
        server.sendmail(sender_email, receiver_email, email_message)
        print(f"OTP sent to {receiver_email}: {otp}")
    except Exception as e:
        print(f"Failed to send email: {e}")
    finally:
        server.quit()

def get_current_hospital():
    with open('current_hospital.json', 'r') as json_file:
        # Load the JSON data into a Python object (typically a dictionary)
        data = json.load(json_file)
    current = data['hospital_name']
    return current
def get_otp():
    curr_hosp = get_current_hospital()
    hospital_ref = db.reference(f'/{curr_hosp}')
    hosp_data = hospital_ref.get()
    otp = hosp_data['OTP']
    return otp
def decrypt_image_file(encrypted_image_path: str, encrypted_key_path: str, private_key_path: str, output_image_path: str):
    # Step 1: Load the RSA private key
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    # Step 2: Read the encrypted AES key
    with open(encrypted_key_path, 'rb') as key_file:
        encrypted_aes_key = key_file.read()

    # Step 3: Decrypt the AES key using RSA private key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 4: Read the encrypted image data
    with open(encrypted_image_path, 'rb') as image_file:
        iv = image_file.read(16)  # Read the IV (the first 16 bytes)
        encrypted_data = image_file.read()  # Read the rest of the file

    # Step 5: Decrypt the image data using AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Step 6: Unpad the decrypted data
    unpadder = aes_padding.PKCS7(algorithms.AES.block_size).unpadder()
    image_data = unpadder.update(padded_data) + unpadder.finalize()

    # Step 7: Save the decrypted image data to a file
    with open(output_image_path, 'wb') as output_file:
        output_file.write(image_data)

    print(f"Decrypted image saved at {output_image_path}")


def verify_hash():
    decrypted_image_path = f'Decryption/{get_current_hospital()}_Decrypted_image.jpg'
    calculated_hash = calculate_image_hash(decrypted_image_path)

    # Path to the received hash value file
    received_hash_path = f'{get_current_hospital()}/hash_value_{get_current_hospital()}.txt'

    # Read the hash value from the text file
    try:
        with open(received_hash_path, 'r') as file:
            received_hash = file.read().strip()  # Read and strip any extra whitespace/newline
    except FileNotFoundError:
        print("Received hash file not found.")
        return False

    # Verify if the calculated hash matches the received hash
    if calculated_hash == received_hash:
        print("Hash verification successful. Image integrity verified.")
        return True
    else:
        print("Hash verification failed. Image integrity compromised.")
        return False








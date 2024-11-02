from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse,RedirectResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import os
import json
import shutil

import utils

app = FastAPI()
app.mount("/Reg", StaticFiles(directory="./Reg"), name="Reg")
app.mount("/Decryption", StaticFiles(directory="./Decryption"), name="Decryption")
app.mount("/uploads", StaticFiles(directory="./uploads"), name="uploads")
# Directory for storing registered hospitals (for demo purposes)
HOSPITALS_DIR = Path("hospitals")
HOSPITALS_DIR.mkdir(parents=True, exist_ok=True)
current_hosp = ""
@app.get("/", response_class=HTMLResponse)
async def home():
    try:
        with open("Reg/Home.html", "r") as file:
            html_content = file.read()
        return HTMLResponse(content=html_content)
    except Exception as e:
        return HTMLResponse(content=f"Error: {str(e)}", status_code=500)


@app.get("/register", response_class=HTMLResponse)
async def get_registration_form():
    # Serve the HTML file for hospital registration
    try:
        with open("Reg/hospital_registration.html", "r") as file:
            html_content = file.read()
        return HTMLResponse(content=html_content)
    except Exception as e:
        return HTMLResponse(content=f"Error: {str(e)}", status_code=500)

@app.get("/login", response_class=HTMLResponse)
async def get_registration_form():
    # Serve the HTML file for hospital registration
    try:
        with open("Reg/Login.html", "r") as file:
            html_content = file.read()
        return HTMLResponse(content=html_content)
    except Exception as e:
        return HTMLResponse(content=f"Error: {str(e)}", status_code=500)
@app.get("/download")
def download_file():
    file_path = "private_key.pem"  # specify the file's path
    return FileResponse(file_path, filename="private_key.pem")
@app.get("/get_encrypted_image/{hospital_name}")
async def get_encrypted_image(hospital_name: str):
    # Construct the file path
    with open('current_hospital.json', 'r') as json_file:
        # Load the JSON data into a Python object (typically a dictionary)
        data = json.load(json_file)
    reciever = data['hospital_name']
    file_path = os.path.join( reciever,f"encrypted_image_{hospital_name}.bin")

    # Check if the file exists
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    # Return the file as a response
    return FileResponse(file_path)

@app.get("/get_AES_key/{hospital_name}")
async def get_encrypted_image(hospital_name: str):
    # Construct the file path
    with open('current_hospital.json', 'r') as json_file:
        # Load the JSON data into a Python object (typically a dictionary)
        data = json.load(json_file)
    reciever = data['hospital_name']
    file_path = os.path.join( reciever,f"encrypted_aes_key_{hospital_name}.bin")

    # Check if the file exists
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    # Return the file as a response
    return FileResponse(file_path)

@app.get("/get_decrypted_image")
async def get_encrypted_image():
    # Construct the file path
    with open('current_hospital.json', 'r') as json_file:
        # Load the JSON data into a Python object (typically a dictionary)
        data = json.load(json_file)
    reciever = data['hospital_name']
    file_path = os.path.join('Decryption',f'{reciever}_Decrypted_image.jpg')

    # Check if the file exists
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    # Return the file as a response
    return FileResponse(file_path, media_type='image/jpeg', filename=f'{reciever}_Decrypted_image.jpg')

@app.get("/dashboard", response_class=HTMLResponse)
async def get_registration_form():
    # Serve the HTML file for hospital registration
    try:
        with open("Reg/Dashboard.html", "r") as file:
            html_content = file.read()
        return HTMLResponse(content=html_content)
    except Exception as e:
        return HTMLResponse(content=f"Error: {str(e)}", status_code=500)
@app.get("/send_image", response_class=HTMLResponse)
async def get_registration_form():
    # Serve the HTML file for hospital registration
    try:
        with open("Reg/send_image.html", "r") as file:
            html_content = file.read()
        return HTMLResponse(content=html_content)
    except Exception as e:
        return HTMLResponse(content=f"Error: {str(e)}", status_code=500)

@app.get("/receive_image", response_class=HTMLResponse)
async def get_registration_form():
    # Serve the HTML file for hospital registration
    try:
        with open("Reg/receive_image.html", "r") as file:
            html_content = file.read()
        return HTMLResponse(content=html_content)
    except Exception as e:
        return HTMLResponse(content=f"Error: {str(e)}", status_code=500)

@app.get("/OTP", response_class=HTMLResponse)
async def get_registration_form():
    # Serve the HTML file for hospital registration
    try:
        with open("Reg/OTP.html", "r") as file:
            html_content = file.read()
        return HTMLResponse(content=html_content)
    except Exception as e:
        return HTMLResponse(content=f"Error: {str(e)}", status_code=500)

@app.get("/Decryption")
async def decryption_page():
    # This can be the decryption page or any content you'd like to serve after OTP verification
    try:
        with open("Reg/decryption.html", "r") as file:
            html_content = file.read()
        return HTMLResponse(content=html_content)
    except Exception as e:
        return HTMLResponse(content=f"Error: {str(e)}", status_code=500)
@app.get("/registered_hospitals")
async def get_hospitals():
    try:
        data = utils.get_hospitals()

        return JSONResponse(content=data)

    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}
@app.post("/register_hospital")
async def register_hospital(
        name: str = Form(...),
        address: str = Form(...),
        contact_email: str = Form(...),
        contact_phone: str = Form(None),
        password: str = Form(...),
):
    try:
        # Generate a unique ID for the hospital
        hospital_id = 1
        hospital_data = {
            "id": hospital_id,
            "name": name,
            "address": address,
            "contact_email": contact_email,
            "contact_phone": contact_phone,
            "password": password
        }

        # Save hospital data in a JSON file
        hospital_data = utils.generateRSA_keys(hospital_data)
        utils.register(hospital_data)

        return JSONResponse(hospital_data)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.post("/login_hospital")
async def login_hospital(
        name: str = Form(...),
        password: str = Form(...)):
    # Fetch hospital data from Firebase
    try:
        login_status,status = utils.login_hospital(name, password)
        if status:
            send = {"hospital_name":name}
            with open('current_hospital.json', 'w') as file:
                json.dump(send, file)
                # Write data to the file


            with open("Reg/redirect.html", "r") as file:
                html_content = file.read()
            return HTMLResponse(content=html_content)


        return JSONResponse(login_status)

    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}


@app.post("/upload_image")
async def upload_image(
    imageFile: UploadFile = File(...),
    hospital: str = Form(...)
):
    try:
        # Define the file path based on hospital name
        file_location = os.path.join("./uploaded_images", f"uploaded_image_{hospital}.jpg")

        # Save the uploaded file to the specified path
        with open(file_location, "wb") as file_object:
            file_object.write(imageFile.file.read())

        # Encrypt the image immediately after saving it
        encrypted_image_path, encrypted_key_path = utils.encrypt_image_with_aes_and_rsa(file_location, hospital)

        with open("Reg/image_uploaded.html", "r") as file:
            html_content = file.read()
        return HTMLResponse(content=html_content)

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/send_OTP")
async def sendOTP():
    try:
        utils.send_otp_via_email()
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/validate_otp")
async def verify_otp(otp: str = Form(...)):

    # Fetch hospital data from Firebase
    print(otp)
    print(utils.get_otp())
    try:
        if(int(utils.get_otp()) == int(otp)):
            print("OTP verified")
            return {"LOGIN": "Successful"}
        else:
            print("OTP verification failed")
            return {"LOGIN": "Failed"}



    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}

decryption_dir = "Decryption"
os.makedirs(decryption_dir, exist_ok=True)


@app.post("/decrypt_image")
async def decrypt_image_file(
        encrypted_image: UploadFile = File(...),
        encrypted_key: UploadFile = File(...),
        private_key: UploadFile = File(...),
):
    try:
        # Save uploaded files to the Decryption directory
        encrypted_image_path = os.path.join(decryption_dir, encrypted_image.filename)
        encrypted_key_path = os.path.join(decryption_dir, encrypted_key.filename)
        private_key_path = os.path.join(decryption_dir, private_key.filename)

        # Save each uploaded file
        with open(encrypted_image_path, 'wb') as image_file:
            image_file.write(await encrypted_image.read())

        with open(encrypted_key_path, 'wb') as key_file:
            key_file.write(await encrypted_key.read())

        with open(private_key_path, 'wb') as key_file:
            key_file.write(await private_key.read())

        output_path = f'Decryption/{utils.get_current_hospital()}_Decrypted_image.jpg'

        utils.decrypt_image_file(encrypted_image_path, encrypted_key_path, private_key_path,output_path)

        # Return a success message
        return {"Status": "Success", "decryptedImageUrl" : output_path}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




from fastapi import FastAPI, UploadFile, File,Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse,RedirectResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import os
import shutil

import utils

app = FastAPI()
app.mount("/Reg", StaticFiles(directory="./Reg"), name="Reg")
app.mount("/uploads", StaticFiles(directory="./uploads"), name="uploads")
# Directory for storing registered hospitals (for demo purposes)
HOSPITALS_DIR = Path("hospitals")
HOSPITALS_DIR.mkdir(parents=True, exist_ok=True)

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

        return JSONResponse(content={
            "message": "Image uploaded and encrypted successfully",
            "file_path": file_location,
            "encrypted_image": encrypted_image_path,
            "encrypted_key": encrypted_key_path
        })

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


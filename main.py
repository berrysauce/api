import os
import boto3
import zipfile
import uvicorn
import datetime
import mimetypes
from jose import jwt
from io import BytesIO
from dotenv import load_dotenv
from typing import Annotated
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from fastapi import FastAPI, Form, File, UploadFile, Request, Security, HTTPException, Depends
from fastapi.responses import RedirectResponse
from fastapi.security import APIKeyCookie
from fastapi_sso.sso.github import GithubSSO
from fastapi_sso.sso.base import OpenID
from tempfile import TemporaryFile


# Environment variables
load_dotenv()
PORT = int(os.getenv("PORT"))
CF_R2_ACCESS_KEY = os.getenv("CF_R2_ACCESS_KEY")
CF_R2_SECRET_KEY = os.getenv("CF_R2_ACCESS_KEY")
CF_R2_ACCOUNT_ID = os.getenv("CF_R2_ACCOUNT_ID")
CF_R2_BUCKET = os.getenv("CF_R2_BUCKET")
CF_R2_REGION = os.getenv("CF_R2_REGION")
JWT_SECRET = os.getenv("JWT_SECRET")
OAUTH_ALLOW_INSECURE = bool(os.getenv("OAUTH_ALLOW_INSECURE"))
OAUTH_SECRET = os.getenv("OAUTH_SECRET")
OAUTH_GH_CLIENT_ID = os.getenv("OAUTH_GH_CLIENT_ID")
OAUTH_GH_CLIENT_SECRET = os.getenv("OAUTH_GH_CLIENT_SECRET")
MONGODB_USER = os.getenv("MONGODB_USER")
MONGODB_PASSWORD = os.getenv("MONGODB_PASSWORD")
MONGODB_URI = f"mongodb+srv://{MONGODB_USER}:{MONGODB_PASSWORD}@stowageserverless.jqe5vea.mongodb.net/?retryWrites=true&w=majority&appName=StowageServerless"


app = FastAPI()

sso = GithubSSO(
    client_id=OAUTH_GH_CLIENT_ID,
    client_secret=OAUTH_GH_CLIENT_SECRET,
    redirect_uri="https://api.stowage.dev/auth/callback",
    allow_insecure_http=OAUTH_ALLOW_INSECURE,
)

aws_session = boto3.Session(
    aws_access_key_id=CF_R2_ACCESS_KEY,
    aws_secret_access_key=CF_R2_SECRET_KEY
)
s3_client = aws_session.client(
    "s3",
    region_name=CF_R2_REGION,
    endpoint_url=f"https://{CF_R2_ACCOUNT_ID}.r2.cloudflarestorage.com/{CF_R2_BUCKET}",
    
)
mongodb_client = MongoClient(MONGODB_URI, server_api=ServerApi("1"))

MAX_FILE_SIZE = 50 * 1024 * 1024 # 50MB max file size limit for uploaded ZIP files
MAX_INDIVIDUAL_FILE_SIZE = 10 * 1024 * 1024  # 10 MB max file size limit for individual files
MAX_DECOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MB total decompressed size
MAX_FILE_COUNT = 1000  # Maximum number of files
MAX_NESTED_DEPTH = 10  # Maximum directory depth
# list with allowed file extensions for static site hosting
ALLOWED_EXTENSIONS = [".html", ".css", ".js", ".ts", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico",
                      ".bmp", ".tiff", ".woff", ".woff2", ".eot", ".ttf", ".otf", ".mp3", ".webm", ".ogg", ".mp4",
                      ".wav", ".mov", ".pdf", ".csv", ".json", ".xml", ".yaml", ".yml", ".md", ".txt", "webmanifest"]

async def validate_file_extension(filename):
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS

async def calculate_decompressed_size(zip_file):
    total_size = 0
    for file_info in zip_file.infolist():
        total_size += file_info.file_size
    return total_size

async def get_max_depth(path):
    return path.count("/")

#async def is_nested_zip(file_name, zip_file):
#    with zip_file.open(file_name) as f:
#        file_like_object = BytesIO(f.read())
#        try:
#            with zipfile.ZipFile(file_like_object) as nested_zip:
#                return True
#        except zipfile.BadZipFile:
#            return False

async def get_logged_user(cookie: str = Security(APIKeyCookie(name="token"))) -> OpenID:
    # Get user's JWT stored in cookie 'token', parse it and return the user's OpenID
    try:
        claims = jwt.decode(cookie, key=JWT_SECRET, algorithms=["HS256"])
        return OpenID(**claims["pld"])
    except Exception as error:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials") from error


@app.get("/")
def get_root():
    return {"detail": "Stowage API"}

@app.get("/api/user")
async def get_user(user: OpenID = Depends(get_logged_user)):
    # This endpoint will say hello to the logged user
    # If the user is not logged, it will return a 401 error from 'get_logged_user'
    return {
        "detail": f"You are very welcome, {user.email}!",
    }

@app.get("/auth/login")
async def get_auth_login():
    # Initialize auth and redirect
    with sso:
        return await sso.get_login_redirect()

@app.get("/auth/callback")
async def get_auth_callback(request: Request):
    # Process login and redirect the user to the protected endpoint
    with sso:
        openid = await sso.verify_and_process(request)
        if not openid:
            raise HTTPException(status_code=401, detail="Authentication failed")
    # Create a JWT with the user's OpenID
    expiration = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1)
    token = jwt.encode({"pld": openid.model_dump(), "exp": expiration, "sub": openid.id}, key=JWT_SECRET, algorithm="HS256")
    response = RedirectResponse(url="/protected")
    response.set_cookie(
        key="token", value=token, expires=expiration
    )  # This cookie will make sure /protected knows the user
    return response
    
@app.get("/auth/logout")
async def get_auth_logout():
    # Forget the user's session
    response = RedirectResponse(url="/protected")
    response.delete_cookie(key="token")
    return response

@app.post("/api/deploy/zip")
async def post_api_deploy_zip(subdomain: Annotated[str, Form()], zip: Annotated[UploadFile, File()], user: OpenID = Depends(get_logged_user)):
    if zip.size > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="Uploaded file is too large, refer to docs.stowage.dev/upload-limits")
    
    file_content = await zip.read()
    file_like_object = BytesIO(file_content)
    
    with zipfile.ZipFile(file_like_object) as z:
        file_list = z.namelist()
        
        # Prevent nested zip files
        #if await is_nested_zip(file_name, z):
        #    raise HTTPException(status_code=400, detail="ZIP file contains nested zip files, refer to docs.stowage.dev/upload-limits")
        
        # Check the total decompressed size
        total_decompressed_size = await calculate_decompressed_size(z)
        if total_decompressed_size > MAX_DECOMPRESSED_SIZE:
            raise HTTPException(status_code=400, detail="Decompressed file size is too large, refer to docs.stowage.dev/upload-limits")

        # Check the number of files
        if len(file_list) > MAX_FILE_COUNT:
            raise HTTPException(status_code=400, detail="Too many files in the ZIP archive, refer to docs.stowage.dev/upload-limits")

        # Check the directory depth
        for file in file_list:
            if await get_max_depth(file) > MAX_NESTED_DEPTH:
                raise HTTPException(status_code=400, detail="ZIP file contains too deeply nested directories, refer to docs.stowage.dev/upload-limits")
        
        if "index.html" not in file_list:
            raise HTTPException(status_code=400, detail="The zip file must contain an 'index.html' file, refer to docs.stowage.dev/upload-limits")
        
        uploaded_files = []
        
        try:
            for file_name in file_list:
                file_size = z.getinfo(file_name).file_size
        
                # Check the individual file size
                if file_size > MAX_INDIVIDUAL_FILE_SIZE:
                    raise HTTPException(status_code=400, detail="Uploaded file is too large, refer to docs.stowage.dev/upload-limits")
                
                with z.open(file_name) as f:
                    if file_name.endswith("/"):
                        continue # Skip directories
                    
                    if not await validate_file_extension(file_name):
                        raise HTTPException(status_code=400, detail="Invalid file extension, refer to docs.stowage.dev/upload-limits")
                    
                    extracted_content = f.read()
                    content_type = mimetypes.guess_type(file_name)[0]
                    s3_client.upload_fileobj(extracted_content, CF_R2_BUCKET, f"{subdomain}/{file_name}")
                    #s3_client.put_object(Bucket=CF_R2_BUCKET, Key=f"{subdomain}/{file_name}", Body=extracted_content, ContentType=content_type)
                    uploaded_files.append(file_name)
        
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="Invalid zip file")
                
    return {"detail": "success", "user": user, "uploaded_files": uploaded_files}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)
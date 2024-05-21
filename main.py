import os
import boto3
import zipfile
import uvicorn
import mimetypes
from io import BytesIO
from dotenv import load_dotenv
from typing import Annotated
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from fastapi import FastAPI, Form, File, UploadFile, Request
from fastapi_sso.sso.github import GithubSSO


# Environment variables
load_dotenv()
AWS_S3_ACCESS_KEY = os.getenv("AWS_S3_ACCESS_KEY")
AWS_S3_SECRET_KEY = os.getenv("AWS_S3_SECRET_KEY")
AWS_S3_BUCKET = os.getenv("AWS_S3_BUCKET")
AWS_S3_REGION = os.getenv("AWS_S3_REGION")
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
    allow_insecure_http=True,
)

aws_session = boto3.Session(
    aws_access_key_id=AWS_S3_ACCESS_KEY,
    aws_secret_access_key=AWS_S3_SECRET_KEY
)
s3_client = aws_session.client("s3")
mongodb_client = MongoClient(MONGODB_URI, server_api=ServerApi("1"))

@app.get("/")
def root():
    try:
        mongodb_client.admin.command('ping')
        print("Pinged your deployment. You successfully connected to MongoDB!")
    except Exception as e:
        print(e)
    return {"msg": "Stowage API"}

@app.get("/auth/login")
async def auth_init():
    """Initialize auth and redirect"""
    with sso:
        return await sso.get_login_redirect()

@app.get("/auth/callback")
async def auth_callback(request: Request):
    """Verify login"""
    with sso:
        user = await sso.verify_and_process(request)
        return user

@app.post("/api/deploy/zip")
async def post_deploy_zip(subdomain: Annotated[str, Form()], zip: Annotated[UploadFile, File()]):
    file_content = await zip.read()
    file_like_object = BytesIO(file_content)
    
    with zipfile.ZipFile(file_like_object) as z:
        file_list = z.namelist()
        uploaded_files = []
        
        for file_name in file_list:
            with z.open(file_name) as f:
                if file_name.endswith("/"):
                    continue # Skip directories
                
                extracted_content = f.read()
                content_type = mimetypes.guess_type(file_name)[0]
                s3_client.put_object(Bucket=AWS_S3_BUCKET, Key=f"{subdomain}/{file_name}", Body=extracted_content, ContentType=content_type)
                uploaded_files.append(file_name)
                
    return {"msg": "success", "uploaded_files": uploaded_files}


if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8000)
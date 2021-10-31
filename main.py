from typing import Optional
from fastapi import FastAPI, Header, HTTPException, status, File, UploadFile, Form
from pydantic import BaseModel
import math
import json

app = FastAPI()

VALID_USERS = {
    "user1": "insecure",
    "user2": "insecure"
}

TOKEN_STR = "Token"
TOKEN = "insecure"


with open("cve.json") as f:
    CVE_DATA = json.load(f)


def filter_func(x, severity):
    try:
        if x["impact"]["baseMetricV2"]["severity"] == severity.upper():
            return x
    except:
        pass

class LoginData(BaseModel):
    username: str
    password: str

@app.post("/upload")
async def upload(data: str = Form(...), upload_file_1: UploadFile = File(...), upload_file_2: UploadFile = File(...)):
    return {"data": data, "f_1": upload_file_1.filename, "f_2": upload_file_2.filename}

@app.post("/login")
async def login(data: LoginData):
    if data.username not in VALID_USERS.keys():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="username or password incorrect")
    if data.password != VALID_USERS[data.username]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="username or password incorrect")
    return {"token": TOKEN}

@app.get("/")
async def root(page: int = 1, per_page: int = 20, severity: str = None, sort_by: str = None, authorization: Optional[str] = Header(None)):
    if authorization == None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing token")

    auth = authorization.split(" ")
    if len(auth)!=2 or auth[0]!=TOKEN_STR:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid token format")

    if auth[1] != TOKEN:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="incorrect token")

    dsc = False
    if page < 1:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="invalid page")
    start = (page - 1) * per_page
    end = page * per_page

    desired = CVE_DATA

    if severity:
        desired = list(filter(lambda x: filter_func(x, severity), desired))

    if sort_by:
        if sort_by not in ["impactScore", "exploitabilityScore", "-impactScore", "-exploitabilityScore"]:
            return {"data": "unknown sort", "status": 400}
        if sort_by.startswith("-"):
            dsc = True
            sort_by = sort_by[1:]
        desired.sort(key=lambda x: x["impact"]["baseMetricV2"][sort_by], reverse=dsc)
    total = math.ceil(len(desired)/per_page)
    if page > total:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="invalid page")
    
    d = dict()
    d["total"] = len(desired)
    d["page_current"] = page
    d["page_total"] = total
    d["data"] = desired[start:end]
    d["status"] = 200
    return d

import os
import hashlib
import secrets
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Product as ProductSchema, Session as SessionSchema

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utilities

def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.sha256((salt + password).encode()).hexdigest()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$")
        return hash_password(password, salt) == stored
    except Exception:
        return False


# Models for requests
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ProductCreateRequest(BaseModel):
    name: str
    price: float
    unit: Optional[str] = None
    description: Optional[str] = None
    image: Optional[str] = None
    in_stock: bool = True


class ProductUpdateRequest(BaseModel):
    name: Optional[str] = None
    price: Optional[float] = None
    unit: Optional[str] = None
    description: Optional[str] = None
    image: Optional[str] = None
    in_stock: Optional[bool] = None


# Auth helpers

def get_user_by_email(email: str) -> Optional[dict]:
    return db["user"].find_one({"email": email})


def create_session(user_id: str) -> str:
    token = secrets.token_hex(24)
    db["session"].insert_one({"user_id": user_id, "token": token})
    return token


def get_user_from_token(token: str) -> Optional[dict]:
    sess = db["session"].find_one({"token": token})
    if not sess:
        return None
    user = db["user"].find_one({"_id": ObjectId(sess["user_id"])})
    return user


@app.get("/")
def read_root():
    return {"message": "POETRACIKAL API ready"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"⚠️ {str(e)[:80]}"
    return response


# Auth endpoints
@app.post("/auth/register")
def register(payload: RegisterRequest):
    if get_user_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email sudah terdaftar")
    pwd = hash_password(payload.password)
    user = UserSchema(name=payload.name, email=payload.email, password_hash=pwd, role="customer")
    user_id = create_document("user", user)
    token = create_session(user_id)
    return {"token": token, "user": {"id": user_id, "name": user.name, "email": user.email, "role": user.role}}


@app.post("/auth/login")
def login(payload: LoginRequest):
    user = get_user_by_email(payload.email)
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Email atau password salah")
    token = create_session(str(user["_id"]))
    return {"token": token, "user": {"id": str(user["_id"]), "name": user["name"], "email": user["email"], "role": user.get("role", "customer")}}


# Products endpoints
@app.get("/products")
def list_products() -> List[dict]:
    docs = get_documents("product")
    result = []
    for d in docs:
        d["id"] = str(d.pop("_id"))
        result.append(d)
    return result


@app.post("/products")
def create_product(payload: ProductCreateRequest, token: Optional[str] = None):
    user = get_user_from_token(token) if token else None
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Hanya admin yang dapat menambah produk")
    prod = ProductSchema(**payload.model_dump())
    prod_id = create_document("product", prod)
    return {"id": prod_id, **payload.model_dump()}


@app.put("/products/{product_id}")
def update_product(product_id: str, payload: ProductUpdateRequest, token: Optional[str] = None):
    user = get_user_from_token(token) if token else None
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Hanya admin yang dapat mengubah produk")
    update_data = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="Tidak ada perubahan")
    res = db["product"].update_one({"_id": ObjectId(product_id)}, {"$set": update_data})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Produk tidak ditemukan")
    doc = db["product"].find_one({"_id": ObjectId(product_id)})
    doc["id"] = str(doc.pop("_id"))
    return doc


@app.delete("/products/{product_id}")
def delete_product(product_id: str, token: Optional[str] = None):
    user = get_user_from_token(token) if token else None
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Hanya admin yang dapat menghapus produk")
    res = db["product"].delete_one({"_id": ObjectId(product_id)})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Produk tidak ditemukan")
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

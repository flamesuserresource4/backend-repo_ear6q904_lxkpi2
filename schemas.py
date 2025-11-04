from pydantic import BaseModel, Field, EmailStr
from typing import Optional

# Each class name determines collection name (lowercased)

class User(BaseModel):
    name: str = Field(..., min_length=2, description="Full name")
    email: EmailStr
    password_hash: str = Field(..., description="Hashed password")
    role: str = Field("customer", description="user role: admin | customer")
    is_active: bool = True

class Product(BaseModel):
    name: str
    description: Optional[str] = None
    price: float = Field(..., ge=0)
    unit: Optional[str] = None
    image: Optional[str] = None
    in_stock: bool = True

class Session(BaseModel):
    user_id: str
    token: str

import os
import re
from datetime import datetime, timedelta
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field, field_validator
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId
from pymongo.errors import CollectionInvalid

# =======================
# Environment Configuration
# =======================

SECRET_KEY = os.getenv("SECRET_KEY")
MONGODB_URL = os.getenv("MONGODB_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME", "organization_management")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

if not SECRET_KEY or not MONGODB_URL:
    raise RuntimeError("Missing required environment variables")

ALGORITHM = "HS256"

# =======================
# Security
# =======================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# =======================
# Database
# =======================

mongodb_client: Optional[AsyncIOMotorClient] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global mongodb_client
    mongodb_client = AsyncIOMotorClient(MONGODB_URL)
    print("✅ MongoDB connected")
    yield
    mongodb_client.close()
    print("❌ MongoDB connection closed")


def get_database():
    return mongodb_client[DATABASE_NAME]


# =======================
# FastAPI App
# =======================

app = FastAPI(
    title="Multi-Tenant Organization Management API",
    description="FastAPI backend with dynamic MongoDB collections",
    version="1.0.0",
    lifespan=lifespan,
)

# =======================
# Models
# =======================

class OrganizationCreate(BaseModel):
    organization_name: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)

    @field_validator("organization_name")
    @classmethod
    def validate_org_name(cls, v):
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            raise ValueError("Invalid organization name")
        return v.lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if len(v.encode("utf-8")) > 72:
            raise ValueError("Password must be at most 72 bytes")
        return v


class OrganizationUpdate(BaseModel):
    organization_name: str
    email: Optional[EmailStr] = None
    password: Optional[str] = None


class OrganizationResponse(BaseModel):
    id: str
    organization_name: str
    email: str
    collection_name: str
    created_at: datetime
    updated_at: datetime


class AdminLogin(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str
    admin_id: str
    organization_id: str
    organization_name: str


class TokenData(BaseModel):
    admin_id: str
    organization_id: str
    organization_name: str


# =======================
# Utilities
# =======================

def get_password_hash(password: str) -> str:
    password = password.encode("utf-8")[:72]
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    password = password.encode("utf-8")[:72]
    return pwd_context.verify(password, hashed)


def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_admin(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return TokenData(
            admin_id=payload["admin_id"],
            organization_id=payload["organization_id"],
            organization_name=payload["organization_name"],
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def generate_collection_name(name: str) -> str:
    return f"org_{name}"


async def create_dynamic_collection(db, name: str):
    collections = await db.list_collection_names()
    if name in collections:
        return
    try:
        await db.create_collection(name)
        await db[name].create_index("created_at")
        await db[name].create_index("updated_at")
    except CollectionInvalid:
        pass


# =======================
# Routes
# =======================

@app.get("/")
async def root():
    return {"status": "running"}


@app.post("/org/create", response_model=OrganizationResponse, status_code=201)
async def create_org(payload: OrganizationCreate):
    db = get_database()

    if await db.organizations.find_one({"organization_name": payload.organization_name}):
        raise HTTPException(400, "Organization already exists")

    collection_name = generate_collection_name(payload.organization_name)
    await create_dynamic_collection(db, collection_name)

    doc = {
        "organization_name": payload.organization_name,
        "admin_email": payload.email,
        "admin_password": get_password_hash(payload.password),
        "collection_name": collection_name,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }

    result = await db.organizations.insert_one(doc)

    return OrganizationResponse(
        id=str(result.inserted_id),
        organization_name=payload.organization_name,
        email=payload.email,
        collection_name=collection_name,
        created_at=doc["created_at"],
        updated_at=doc["updated_at"],
    )


@app.post("/admin/login", response_model=Token)
async def admin_login(data: AdminLogin):
    db = get_database()
    org = await db.organizations.find_one({"admin_email": data.email})

    if not org or not verify_password(data.password, org["admin_password"]):
        raise HTTPException(401, "Invalid credentials")

    token = create_access_token(
        {
            "admin_id": str(org["_id"]),
            "organization_id": str(org["_id"]),
            "organization_name": org["organization_name"],
        }
    )

    return Token(
        access_token=token,
        token_type="bearer",
        admin_id=str(org["_id"]),
        organization_id=str(org["_id"]),
        organization_name=org["organization_name"],
    )


@app.get("/health")
async def health():
    db = get_database()
    await db.command("ping")
    return {"status": "healthy"}

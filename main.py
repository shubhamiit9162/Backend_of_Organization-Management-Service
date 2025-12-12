from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional, List
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import re
from bson import ObjectId
from contextlib import asynccontextmanager
from pymongo.errors import CollectionInvalid

SECRET_KEY = "jdnjdbflNBFbwlfhbRIFUBQEUFAB1223232BJBAFJNBFOL"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
MONGODB_URL = "mongodb+srv://wedding9162:wedding9162@cluster0.d0ffyuz.mongodb.net/?appName=Cluster0"
DATABASE_NAME = "organization_management"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

mongodb_client: Optional[AsyncIOMotorClient] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global mongodb_client
    mongodb_client = AsyncIOMotorClient(MONGODB_URL)
    print("✅ Connected to MongoDB")
    yield
    mongodb_client.close()
    print("❌ Closed MongoDB connection")

app = FastAPI(
    title="Multi-Tenant Organization Management API",
    description="A scalable backend service for managing organizations with dynamic collections",
    version="1.0.0",
    lifespan=lifespan
)

def get_database():
    return mongodb_client[DATABASE_NAME]

class OrganizationCreate(BaseModel):
    organization_name: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)

    @field_validator('organization_name')
    @classmethod
    def validate_org_name(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Organization name must contain only alphanumeric characters, hyphens, and underscores')
        return v.lower()

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if len(v.encode("utf-8")) > 72:
            raise ValueError("Password must be at most 72 bytes")
        return v

class OrganizationUpdate(BaseModel):
    organization_name: str = Field(..., min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8)

    @field_validator('organization_name')
    @classmethod
    def validate_org_name(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Organization name must contain only alphanumeric characters, hyphens, and underscores')
        return v.lower()

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if v is None:
            return v
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if len(v.encode("utf-8")) > 72:
            raise ValueError("Password must be at most 72 bytes")
        return v

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

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        admin_id: str = payload.get("admin_id")
        organization_id: str = payload.get("organization_id")
        organization_name: str = payload.get("organization_name")
        
        if admin_id is None or organization_id is None:
            raise credentials_exception
        
        token_data = TokenData(
            admin_id=admin_id,
            organization_id=organization_id,
            organization_name=organization_name
        )
        return token_data
    except JWTError:
        raise credentials_exception

def generate_collection_name(org_name: str) -> str:
    return f"org_{org_name}"

async def create_dynamic_collection(db, collection_name: str):
    try:
        existing_collections = await db.list_collection_names()
        if collection_name in existing_collections:
            print(f"ℹ️  Collection {collection_name} already exists, skipping creation")
            return True
        
        await db.create_collection(
            collection_name,
            validator={
                '$jsonSchema': {
                    'bsonType': 'object',
                    'properties': {
                        'created_at': {'bsonType': 'date'},
                        'updated_at': {'bsonType': 'date'}
                    }
                }
            }
        )
        
        collection = db[collection_name]
        await collection.create_index("created_at")
        await collection.create_index("updated_at")
        
        print(f"✅ Successfully created collection: {collection_name}")
        return True
    except CollectionInvalid as e:
        print(f"ℹ️  Collection {collection_name} already exists: {e}")
        return True
    except Exception as e:
        print(f"❌ Error creating collection {collection_name}: {e}")
        return False

async def collection_exists(db, collection_name: str) -> bool:
    existing_collections = await db.list_collection_names()
    return collection_name in existing_collections

@app.get("/")
async def root():
    return {
        "message": "Multi-Tenant Organization Management API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "create_organization": "POST /org/create",
            "get_organization": "GET /org/get?organization_name=<name>",
            "update_organization": "PUT /org/update",
            "delete_organization": "DELETE /org/delete?organization_name=<name>",
            "admin_login": "POST /admin/login",
            "list_organizations": "GET /org/list",
            "collection_stats": "GET /org/collection/stats"
        }
    }

@app.post("/org/create", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(org_data: OrganizationCreate):
    db = get_database()
    
    existing_org = await db.organizations.find_one({"organization_name": org_data.organization_name})
    if existing_org:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Organization '{org_data.organization_name}' already exists"
        )
    
    existing_email = await db.organizations.find_one({"admin_email": org_data.email})
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered with another organization"
        )
    
    collection_name = generate_collection_name(org_data.organization_name)
    
    if await collection_exists(db, collection_name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Collection for organization '{org_data.organization_name}' already exists. Please use a different name or contact support."
        )
    
    collection_created = await create_dynamic_collection(db, collection_name)
    if not collection_created:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create organization collection"
        )
    
    hashed_password = get_password_hash(org_data.password)
    
    organization_doc = {
        "organization_name": org_data.organization_name,
        "admin_email": org_data.email,
        "admin_password": hashed_password,
        "collection_name": collection_name,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "is_active": True
    }
    
    result = await db.organizations.insert_one(organization_doc)
    
    return OrganizationResponse(
        id=str(result.inserted_id),
        organization_name=org_data.organization_name,
        email=org_data.email,
        collection_name=collection_name,
        created_at=organization_doc["created_at"],
        updated_at=organization_doc["updated_at"]
    )

@app.get("/org/get", response_model=OrganizationResponse)
async def get_organization(organization_name: str):
    db = get_database()
    
    org = await db.organizations.find_one({"organization_name": organization_name.lower()})
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization '{organization_name}' not found"
        )
    
    return OrganizationResponse(
        id=str(org["_id"]),
        organization_name=org["organization_name"],
        email=org["admin_email"],
        collection_name=org["collection_name"],
        created_at=org["created_at"],
        updated_at=org["updated_at"]
    )

@app.put("/org/update", response_model=OrganizationResponse)
async def update_organization(
    org_update: OrganizationUpdate,
    current_admin: TokenData = Depends(get_current_admin)
):
    db = get_database()
    
    current_org = await db.organizations.find_one({"_id": ObjectId(current_admin.organization_id)})
    if not current_org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )
    
    if org_update.organization_name != current_org["organization_name"]:
        existing_org = await db.organizations.find_one({"organization_name": org_update.organization_name})
        if existing_org:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Organization name '{org_update.organization_name}' already exists"
            )
        
        new_collection_name = generate_collection_name(org_update.organization_name)
        
        if await collection_exists(db, new_collection_name):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Collection for organization '{org_update.organization_name}' already exists. Please use a different name."
            )
        
        await create_dynamic_collection(db, new_collection_name)
        
        old_collection = db[current_org["collection_name"]]
        new_collection = db[new_collection_name]
        
        async for document in old_collection.find():
            await new_collection.insert_one(document)
        
        await old_collection.drop()
        print(f"✅ Migrated data from {current_org['collection_name']} to {new_collection_name}")
    else:
        new_collection_name = current_org["collection_name"]
    
    update_doc = {
        "organization_name": org_update.organization_name,
        "collection_name": new_collection_name,
        "updated_at": datetime.utcnow()
    }
    
    if org_update.email:
        existing_email = await db.organizations.find_one({
            "admin_email": org_update.email,
            "_id": {"$ne": ObjectId(current_admin.organization_id)}
        })
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered with another organization"
            )
        update_doc["admin_email"] = org_update.email
    
    if org_update.password:
        update_doc["admin_password"] = get_password_hash(org_update.password)
    
    await db.organizations.update_one(
        {"_id": ObjectId(current_admin.organization_id)},
        {"$set": update_doc}
    )
    
    updated_org = await db.organizations.find_one({"_id": ObjectId(current_admin.organization_id)})
    
    return OrganizationResponse(
        id=str(updated_org["_id"]),
        organization_name=updated_org["organization_name"],
        email=updated_org["admin_email"],
        collection_name=updated_org["collection_name"],
        created_at=updated_org["created_at"],
        updated_at=updated_org["updated_at"]
    )

@app.delete("/org/delete", status_code=status.HTTP_200_OK)
async def delete_organization(
    organization_name: str,
    current_admin: TokenData = Depends(get_current_admin)
):
    db = get_database()
    
    if current_admin.organization_name != organization_name.lower():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only delete your own organization"
        )
    
    org = await db.organizations.find_one({"organization_name": organization_name.lower()})
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization '{organization_name}' not found"
        )
    
    collection = db[org["collection_name"]]
    await collection.drop()
    print(f"✅ Dropped collection: {org['collection_name']}")
    
    await db.organizations.delete_one({"_id": org["_id"]})
    print(f"✅ Deleted organization: {organization_name}")
    
    return {
        "message": f"Organization '{organization_name}' and its data have been successfully deleted",
        "deleted_collection": org["collection_name"]
    }

@app.post("/admin/login", response_model=Token)
async def admin_login(login_data: AdminLogin):
    db = get_database()
    
    org = await db.organizations.find_one({"admin_email": login_data.email})
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    if not verify_password(login_data.password, org["admin_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    if not org.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization is deactivated"
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "admin_id": str(org["_id"]),
            "organization_id": str(org["_id"]),
            "organization_name": org["organization_name"],
            "email": org["admin_email"]
        },
        expires_delta=access_token_expires
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        admin_id=str(org["_id"]),
        organization_id=str(org["_id"]),
        organization_name=org["organization_name"]
    )

@app.get("/org/list", response_model=List[OrganizationResponse])
async def list_organizations(
    skip: int = 0,
    limit: int = 10,
    current_admin: TokenData = Depends(get_current_admin)
):
    db = get_database()
    
    cursor = db.organizations.find().skip(skip).limit(limit)
    organizations = await cursor.to_list(length=limit)
    
    return [
        OrganizationResponse(
            id=str(org["_id"]),
            organization_name=org["organization_name"],
            email=org["admin_email"],
            collection_name=org["collection_name"],
            created_at=org["created_at"],
            updated_at=org["updated_at"]
        )
        for org in organizations
    ]

@app.get("/org/collection/stats")
async def get_collection_stats(current_admin: TokenData = Depends(get_current_admin)):
    db = get_database()
    
    org = await db.organizations.find_one({"_id": ObjectId(current_admin.organization_id)})
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )
    
    collection = db[org["collection_name"]]
    
    document_count = await collection.count_documents({})
    indexes = await collection.index_information()
    
    return {
        "organization_name": org["organization_name"],
        "collection_name": org["collection_name"],
        "document_count": document_count,
        "indexes": list(indexes.keys()),
        "created_at": org["created_at"],
        "updated_at": org["updated_at"]
    }

@app.get("/health")
async def health_check():
    try:
        db = get_database()
        await db.command("ping")
        return {
            "status": "healthy",
            "service": "Organization Management API",
            "database": "connected"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "service": "Organization Management API",
            "database": "disconnected",
            "error": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
from datetime import timedelta, datetime, timezone
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import Users
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError, jwe
import os
import secrets

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

# Encryption and Security Configuration
ENCRYPTION_KEY = os.urandom(32)  # 256-bit key
ENCRYPTION_ALGORITHM = 'A256GCM'
SIGNING_SECRET_KEY = secrets.token_hex(32)  # More secure secret key generation
SIGNING_ALGORITHM = 'HS256'

# Token Configurations
ACCESS_TOKEN_EXPIRE_MINUTES = 20
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Context and Security Setup
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')

class CreateUserRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_at: datetime

class RefreshTokenRequest(BaseModel):
    refresh_token: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

class TokenManager:
    @staticmethod
    def create_encrypted_token(username: str, user_id: int, expires_delta: timedelta, is_refresh: bool = False):
        """
        Create an encrypted JWE token with enhanced claims
        """
        jwt_payload = {
            'sub': username,
            'id': user_id,
            'type': 'refresh' if is_refresh else 'access',
            'exp': datetime.now(timezone.utc) + expires_delta
        }
        
        # First, sign the payload with JWT
        signed_token = jwt.encode(jwt_payload, SIGNING_SECRET_KEY, algorithm=SIGNING_ALGORITHM)
        
        # Then encrypt the signed token
        encrypted_token = jwe.encrypt(
            signed_token, 
            ENCRYPTION_KEY, 
            encryption=ENCRYPTION_ALGORITHM
        )
        
        return encrypted_token.decode('utf-8')

    @staticmethod
    def decrypt_and_validate_token(encrypted_token: str):
        """
        Decrypt JWE token and validate its contents
        """
        try:
            # Decrypt the token
            decrypted_token = jwe.decrypt(
                encrypted_token.encode('utf-8'), 
                ENCRYPTION_KEY
            ).decode('utf-8')
            
            # Verify and decode the JWT
            payload = jwt.decode(
                decrypted_token, 
                SIGNING_SECRET_KEY, 
                algorithms=[SIGNING_ALGORITHM]
            )
            
            return payload
        except (jwe.JWEError, jwt.JWTError) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail=f'Token validation failed: {str(e)}'
            )

class AuthService:
    @staticmethod
    def authenticate_user(username: str, password: str, db):
        """
        Authenticate user credentials
        """
        user = db.query(Users).filter(Users.username == username).first()
        if not user:
            return False
        if not bcrypt_context.verify(password, user.hashed_password):
            return False
        return user

    @staticmethod
    def create_tokens(user):
        """
        Create access and refresh tokens
        """
        access_token = TokenManager.create_encrypted_token(
            user.username, 
            user.id, 
            timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        refresh_token = TokenManager.create_encrypted_token(
            user.username, 
            user.id, 
            timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
            is_refresh=True
        )
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_at': datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        }

# Authentication Endpoints
@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, create_user_request: CreateUserRequest):
    """
    User Registration Endpoint
    """
    create_user_model = Users(
        username=create_user_request.username,
        hashed_password=bcrypt_context.hash(create_user_request.password)
    )
    db.add(create_user_model)
    db.commit()
    return {"message": "User created successfully"}

@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], 
    db: db_dependency
):
    """
    User Login and Token Generation Endpoint
    """
    user = AuthService.authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Could not validate user"
        )
    
    # Create tokens
    tokens = AuthService.create_tokens(user)
    
    return {
        'access_token': tokens['access_token'], 
        'refresh_token': tokens['refresh_token'],
        'token_type': 'bearer',
        'expires_at': tokens['expires_at']
    }

@router.post("/refresh")
async def refresh_access_token(
    refresh_token: Annotated[RefreshTokenRequest, Depends()],
    db: db_dependency
):
    """
    Refresh Access Token Endpoint
    """
    try:
        # Decrypt and validate refresh token
        payload = TokenManager.decrypt_and_validate_token(refresh_token.refresh_token)
        
        # Additional validation for refresh token
        if payload.get('type') != 'refresh':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid refresh token"
            )
        
        # Find user in database
        user = db.query(Users).filter(Users.username == payload.get('sub')).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="User not found"
            )
        
        # Create new access token
        new_access_token = TokenManager.create_encrypted_token(
            user.username, 
            user.id, 
            timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        return {
            'access_token': new_access_token,
            'token_type': 'bearer',
            'expires_at': datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        }
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Could not validate refresh token"
        )

async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    """
    Get Current User from Access Token
    """
    try:
        payload = TokenManager.decrypt_and_validate_token(token)
        
        # Additional validation for access token
        if payload.get('type') != 'access':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid access token"
            )
        
        return {
            'username': payload.get('sub'),
            'id': payload.get('id')
        }
    except HTTPException as e:
        raise e
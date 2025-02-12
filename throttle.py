from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from fastapi_login import LoginManager
from passlib.context import CryptContext
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import jwt
import os
from db import users
from dotenv import load_dotenv
from fastapi.responses import JSONResponse
from sqlalchemy.sql import text
from fastapi.encoders import jsonable_encoder
from fastapi import Form
from openai import OpenAI
from fastapi.responses import StreamingResponse
import asyncio
from fastapi import FastAPI, Depends, Request, HTTPException, Response
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
import redis.asyncio as redis


class CustomOAuth2PasswordRequestForm:
    def __init__(self, username: str = Form(...), password: str = Form(...), email: str = Form(...),project: str = Form(...)):
        self.username = username
        self.password = password
        self.email = email
        self.project = project

#Setup Environment Variables
load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')
ACCESS_TOKEN_EXPIRES_MINUTES = 3

templates = Jinja2Templates(directory="templates")
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")


#Load Models
class User(BaseModel):
    name: str
    username: str
    email: str
    birthday: Optional[str] = ""
    friends: Optional[List[str]] = []

class UserDB(User):
    hashed_password: str

#Utilities
client = OpenAI()

manager = LoginManager(secret=SECRET_KEY,token_url="/login", use_cookie=True)
manager.cookie_name = "auth"

system_prompt={ 'role':'system', 'content':'You are a helpful assistant Arnie Keep your responses under 50 words' }
conversation_history=[system_prompt]

# Password hashing
pwd_ctx = CryptContext(schemes=["bcrypt"],deprecated="auto")

@app.on_event("startup")
async def startup():
    # redis_client = redis.Redis(host="localhost", port=6379, db=0)
    redis_client = redis.from_url("redis://:your_redis_password@localhost:6378", encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(redis_client)

def get_client_ip(request: Request) -> str:
    return request.client.host  # Extracts user IP from request
# Simulated function to get limits based on IP address
async def get_ip_limits(request: Request):
    # Get client IP address
    client_ip = request.client.host
    
    # Define IP-based limits (you can customize these)
    ip_limits = {
        "127.0.0.1": (5, 30),    # localhost gets 5 requests per half minute
        "192.168.1.1": (20, 60),   # specific IP gets 20 requests per minute
        # Add more IP-specific limits as needed
    }
    
    # Default to 5 requests per minute for unknown IPs
    return ip_limits.get(client_ip, (5, 60))

# Custom RateLimiter Dependency
async def custom_ip_limiter(request: Request, response: Response):
    times, seconds = await get_ip_limits(request)
    return await RateLimiter(times=times, seconds=seconds)(request,response)

# Custom exception handler for rate limiting
@app.exception_handler(HTTPException)
async def rate_limit_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 429:
        user_ip = get_client_ip(request)
        return JSONResponse(
            status_code=429,
            content={
                "error": "Too Many Requests",
                "message": f"Rate limit exceeded for IP: {user_ip}",
                "retry_after": "Wait before retrying.",
                "status": "Blocked"
            },
            headers={"Retry-After": "60"}  # Retry after 60 seconds
        )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


def authenticate_user(username: str, password: str):
    user = get_user_from_db(username=username)
    if not user:
        return None
    if not verify_password(plain_password=password, hashed_password=user.hashed_password):
        return None
    return user

def get_hashed_password(plain_password):
    return pwd_ctx.hash(plain_password)

def verify_password(plain_password, hashed_password):
    return pwd_ctx.verify(plain_password,hashed_password)

@manager.user_loader()
def get_user_from_db(username: str):
    if username in users.keys():
        return UserDB(**users[username])

@app.get("/", response_class=HTMLResponse)
def root(request: Request,):
    return templates.TemplateResponse("index.html", {"request": request, "title": "Throttle"})

@app.get("/login",response_class=HTMLResponse)
def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "title": "Login"})

@app.get("/register",response_class=HTMLResponse)
def register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "title": "Register"})

async def stream_response(message):
    response=""
    conversation_history.append({'role':'user','content':message})
    response = client.chat.completions.create(messages=conversation_history,model="gpt-4o-mini",stream=True)
    for chunk in response:
        if chunk.choices[0].delta.content is not None:
            #response+=chunk.choices[0].delta.content
            yield chunk.choices[0].delta.content
            await asyncio.sleep(0.01)
    conversation_history.append({'role':'assistant','content':response})

@app.post("/chat",response_class=StreamingResponse,dependencies=[Depends(custom_ip_limiter)])
async def chat(request: Request,tokens: str = Depends(manager)):
    json_data = await request.json()
    message = json_data.get("message", "")
    
    return StreamingResponse(stream_response(message),media_type="text/plain")
    
@app.post("/register")
async def register_user(request: Request, form_data: CustomOAuth2PasswordRequestForm = Depends()):
    hashed_password = get_hashed_password(form_data.password)
    invalid = False
    for db_username in users.keys():
        if form_data.username == db_username:
            invalid = True
        elif users[db_username]["email"] == form_data.email:
            invalid = True
    
    if invalid:
        return templates.TemplateResponse("register.html",{"request": request, "title": "FriendConnect - Register", "invalid": True},status_code=status.HTTP_400_BAD_REQUEST)
    
    users[form_data.username] = jsonable_encoder(UserDB(username=form_data.username,email=form_data.email,name=form_data.project,hashed_password=hashed_password))
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES)
    access_token = manager.create_access_token(
        data={"sub": form_data.username},
        expires=access_token_expires
    )
    resp = RedirectResponse("/home", status_code=status.HTTP_302_FOUND)
    manager.set_cookie(resp,access_token)
    return resp

@app.post("/authorize")
async def login(request: Request,form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(username=form_data.username, password=form_data.password)
    if not user:
        return templates.TemplateResponse("login.html", {"request": request, "title": "Throttle - Login", "invalid": True}, status_code=status.HTTP_401_UNAUTHORIZED)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES)
    access_token = manager.create_access_token(
        data={"sub": user.username},
        expires=access_token_expires
    )
    resp = RedirectResponse("/home", status_code=status.HTTP_302_FOUND)
    manager.set_cookie(resp,access_token)
    return resp

@app.get("/home", response_class=HTMLResponse,dependencies=[Depends(custom_ip_limiter)])
def root(request: Request,):#tokens: str = Depends(manager)
    try:
        return templates.TemplateResponse("home.html", {"request": request, "title": "Throttle"})
    except:
        return templates.TemplateResponse("404.html", {"request": request, "title": "Not Found"}, status_code=404)
    
    

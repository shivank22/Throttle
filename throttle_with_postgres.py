from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_login import LoginManager
from passlib.context import CryptContext
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import jwt
import os
from dotenv import load_dotenv
from fastapi.responses import JSONResponse
from sqlalchemy.sql import text

#Setup Environment Variables
load_dotenv()
POSTGRES_USER = os.getenv("POSTGRES_USER")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
SECRET_KEY = os.getenv('SECRET_KEY')
ACCESS_TOKEN_EXPIRES_MINUTES = 3

templates = Jinja2Templates(directory="templates")
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

# Database setup
SQLALCHEMY_DATABASE_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@localhost/postgres"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

#Load Models
class User(Base):
    __tablename__ = "user_login"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    email = Column(String, nullable=True)
    project = Column(String, nullable=True)

#This statement syncs the models with the database
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


#Utilities

manager = LoginManager(secret=SECRET_KEY,token_url="/login", use_cookie=True)
manager.cookie_name = "auth"

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@manager.user_loader()
def get_users_from_db(username: str):
    with SessionLocal() as db:
        user = (db.query(User.username).filter(User.username == username).first())
        return user

@app.get("/", response_class=HTMLResponse)
def root(request: Request,):
    return templates.TemplateResponse("index.html", {"request": request, "title": "Throttle"})

@app.get("/login",response_class=HTMLResponse)
def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "title": "Login"})

@app.get("/register",response_class=HTMLResponse)
def register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "title": "Register"})

@app.post("/chat")
async def chat(request: Request,tokens: str = Depends(manager)):
    return {"message": "Hello!"}

@app.post("/register")
async def register_user(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    # Check if user already exists
    existing_user = db.query(User).filter(User.username == form_data.username).first()
    if existing_user:
        return templates.TemplateResponse(
            "register.html", 
            {
                "request": request, 
                "title": "Registration Failed", 
                "invalid": True, 
                "detail": "Username already exists"
            },
            status_code=status.HTTP_400_BAD_REQUEST
        )

    # Create new user
    hashed_password = pwd_context.hash(form_data.password)
    new_user = User(username=form_data.username, hashed_password=hashed_password)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES)
    access_token = manager.create_access_token(
        data={"sub": new_user.username},
        expires=access_token_expires
    )
    resp = RedirectResponse("/home", status_code=status.HTTP_302_FOUND)
    manager.set_cookie(resp,access_token)
    return resp

@app.post("/authorize")
async def login(request: Request,form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):

    # oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
    
    user = db.query(User).filter(User.username == form_data.username).first()
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

@app.get("/home", response_class=HTMLResponse)
def root(request: Request,tokens: str = Depends(manager)):
    try:
        return templates.TemplateResponse("home.html", {"request": request, "title": "Throttle"})
    except:
        return templates.TemplateResponse("404.html", {"request": request, "title": "Not Found"}, status_code=404)
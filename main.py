import os
import sqlite3
import secrets
import smtplib
from email.message import EmailMessage
from fastapi import FastAPI, Form, Request, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

# Configurazione
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
DB_PATH = os.getenv("DB_PATH", "users.db")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", "")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        confirmed INTEGER DEFAULT 0,
        confirm_token TEXT
    )
    """)
    conn.commit()
    conn.close()
init_db()

def send_verification_email(to_email, token):
    verify_url = f"{BASE_URL}/confirm?token={token}"
    msg = EmailMessage()
    msg['Subject'] = "Conferma la tua registrazione"
    msg['From'] = FROM_EMAIL
    msg['To'] = to_email
    msg.set_content(f"Clicca qui per confermare: {verify_url}")
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
    except Exception as e:
        print(f"Errore invio email: {e}")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(email):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, email, password, role, confirmed FROM users WHERE email=?", (email,))
    row = c.fetchone()
    conn.close()
    return row

def get_user_by_token(token):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, email, confirmed FROM users WHERE confirm_token=?", (token,))
    row = c.fetchone()
    conn.close()
    return row

def confirm_user(token):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET confirmed=1, confirm_token=NULL WHERE confirm_token=?", (token,))
    conn.commit()
    conn.close()

def authenticate_user(email, password):
    user = get_user(email)
    if not user:
        return False
    if not pwd_context.verify(password, user[2]):
        return False
    if not user[4]:
        return False
    return user

def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        user = get_user(email)
        return user
    except JWTError:
        return None

# Home page
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = get_current_user(request)
    return templates.TemplateResponse("home.html", {"request": request, "user": user})

# Pagina di registrazione
@app.get("/register", response_class=HTMLResponse)
async def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

# Registrazione utente
@app.post("/register", response_class=HTMLResponse)
async def register(request: Request, email: str = Form(...), password: str = Form(...)):
    hashed_password = pwd_context.hash(password)
    token = secrets.token_urlsafe(32)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (email, password, confirm_token) VALUES (?, ?, ?)", (email, hashed_password, token))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return templates.TemplateResponse("register.html", {"request": request, "error": "Email già registrata!"})
    conn.close()
    send_verification_email(email, token)
    return templates.TemplateResponse("message.html", {"request": request, "message": "Registrazione avvenuta! Controlla la mail per confermare."})

# Conferma email
@app.get("/confirm", response_class=HTMLResponse)
async def confirm(request: Request, token: str):
    user = get_user_by_token(token)
    if not user:
        return templates.TemplateResponse("message.html", {"request": request, "message": "Token non valido!"})
    confirm_user(token)
    return templates.TemplateResponse("message.html", {"request": request, "message": "Email confermata! Ora puoi effettuare il login."})

# Pagina di login
@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# Login utente
@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, email: str = Form(...), password: str = Form(...)):
    user = authenticate_user(email, password)
    if not user:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Credenziali non valide o email non confermata."})
    access_token = create_access_token({"sub": email})
    response = RedirectResponse("/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

# Dashboard utente
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

# Logout
@app.get("/logout")
async def logout():
    response = RedirectResponse("/")
    response.delete_cookie("access_token")
    return response

# Pagina di recupero password (placeholder)
@app.get("/forgot", response_class=HTMLResponse)
async def forgot_form(request: Request):
    return templates.TemplateResponse("forgot.html", {"request": request})

# Puoi aggiungere altre pagine e funzionalità (gestione ruoli, profili, ecc.)
from fastapi import Form
@app.post("/test-email")
async def test_email(to_email: str = Form(...)):
    send_verification_email(to_email, "https://esempio.com/verifica")
    return {"message": f"Email inviata a {to_email}"}
import os
import httpx
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")  # Deve essere la Service Key
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
FROM_EMAIL = os.getenv("FROM_EMAIL")

app = FastAPI()

def send_verification_email(to_email, verify_url):
    import logging
    msg = EmailMessage()
    msg['Subject'] = "Conferma la tua registrazione"
    msg['From'] = FROM_EMAIL
    msg['To'] = to_email
    msg.set_content(f"Clicca qui per confermare: {verify_url}")
    # msg.add_alternative(...) # puoi aggiungere HTML

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        logging.info(f"Email inviata con successo a {to_email}")
    except Exception as e:
        logging.error(f"Errore invio email a {to_email}: {e}")

@app.post("/register")
async def register(email: str = Form(...), password: str = Form(...)):
    # 1. Crea utente su Supabase
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SUPABASE_URL}/auth/v1/signup",
            json={"email": email, "password": password},
            headers={"apikey": SUPABASE_KEY, "Content-Type": "application/json"}
        )
        if resp.status_code != 200:
            return {"error": "Errore creazione utente"}
        user = resp.json()
    # 2. Genera link di verifica custom
    verify_url = f"https://verifica-successo.vercel.app/verify?email={email}"
    # 3. Invia email personalizzata
    send_verification_email(email, verify_url)
    return {"message": "Registrazione avvenuta. Controlla la mail per confermare."}

@app.get("/verify", response_class=HTMLResponse)
async def verify(email: str):
    # 4. Aggiorna manualmente il campo confirmed_at su Supabase
    import logging
    async with httpx.AsyncClient() as client:
        # Prendi l'id utente
        resp = await client.get(
            f"{SUPABASE_URL}/rest/v1/users?email=eq.{email}",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
        )
        logging.info(f"Risposta Supabase: {resp.status_code} - {resp.text}")
        data = resp.json()
        if resp.status_code != 200 or not data:
            return f"Utente non trovato. Risposta Supabase: {resp.text}"
        user_id = data[0].get('id')
        # Aggiorna confirmed_at
        patch_resp = await client.patch(
            f"{SUPABASE_URL}/rest/v1/users?id=eq.{user_id}",
            json={"confirmed_at": "now()"},
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}", "Content-Type": "application/json"}
        )
        logging.info(f"Patch risposta: {patch_resp.status_code} - {patch_resp.text}")
    return "<h1>✅ Verifica completata!</h1>"

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
    msg = EmailMessage()
    msg['Subject'] = "Conferma la tua registrazione"
    msg['From'] = FROM_EMAIL
    msg['To'] = to_email
    msg.set_content(f"Clicca qui per confermare: {verify_url}")
    # msg.add_alternative(...) # puoi aggiungere HTML

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

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
    async with httpx.AsyncClient() as client:
        # Prendi l'id utente
        resp = await client.get(
            f"{SUPABASE_URL}/rest/v1/users?email=eq.{email}",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
        )
        if resp.status_code != 200 or not resp.json():
            return "Utente non trovato"
        user_id = resp.json()[0]['id']
        # Aggiorna confirmed_at
        await client.patch(
            f"{SUPABASE_URL}/rest/v1/users?id=eq.{user_id}",
            json={"confirmed_at": "now()"},
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}", "Content-Type": "application/json"}
        )
    return "<h1>✅ Verifica completata!</h1>"

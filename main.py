import os, uuid, hashlib, psycopg2
from typing import Optional, List
from datetime import datetime, timedelta, date
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from psycopg2.extras import RealDictCursor
from jose import jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Scanneler Bypass API v3")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# --- CONFIGURACIÓN DB (RECUERDA CAMBIAR LA URL EN RENDER) ---
DB_URL = os.getenv("DATABASE_URL") # Configura esto en Render Dashboard

def get_db():
    conn = psycopg2.connect(DB_URL)
    return conn

def hash_pwd(p): return hashlib.sha256(p.encode()).hexdigest()

# --- MODELOS ---
class KeyGen(BaseModel):
    membresia: str
    duracion_dias: int
    cantidad: int

class UserReg(BaseModel):
    key_code: str
    username: str
    password: str
    hwid: str

# --- ENDPOINTS ---
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = get_db()
    cursor = db.cursor(cursor_factory=RealDictCursor)
    # Buscamos por usuario y clave hash
    cursor.execute("SELECT * FROM bypass_users WHERE username = %s AND password = %s", 
                   (form_data.username, hash_pwd(form_data.password)))
    user = cursor.fetchone()
    
    if not user: raise HTTPException(401, "Credenciales inválidas")
    
    # Lógica de HWID: Si el usuario es nuevo ('NONE'), registramos su PC. 
    # Si ya tiene una, comparamos.
    client_hwid = os.getenv("HTTP_X_HWID", "NONE") # Recibido desde logic.py
    
    if user['hwid'] == 'NONE':
        cursor.execute("UPDATE bypass_users SET hwid = %s WHERE id = %s", (client_hwid, user['id']))
        db.commit()
    elif user['hwid'] != client_hwid and client_hwid != "NONE":
        raise HTTPException(403, "HWID Mismatch: Esta cuenta pertenece a otra PC")

    return {"access_token": "token-falso-sesion", "token_type": "bearer", "role": user['role'], "membresia": user['membresia']}

@app.post("/keys/generate")
def gen_keys(payload: KeyGen):
    db = get_db()
    cursor = db.cursor()
    new_keys = []
    for _ in range(payload.cantidad):
        code = f"SCAN-{uuid.uuid4().hex[:12].upper()}"
        cursor.execute("INSERT INTO bypass_keys (key_string, membresia, duracion_dias) VALUES (%s, %s, %s)",
                       (code, payload.membresia, payload.duracion_dias))
        new_keys.append(code)
    db.commit()
    return {"keys": new_keys}

@app.get("/users")
def get_users():
    db = get_db()
    cursor = db.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT username, role, membresia, vencimiento, hwid FROM bypass_users")
    return cursor.fetchall()

@app.put("/users/{username}/reset-hwid")
def reset_hwid(username: str):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE bypass_users SET hwid = 'NONE' WHERE username = %s", (username,))
    db.commit()
    return {"message": "HWID Reseteado"}
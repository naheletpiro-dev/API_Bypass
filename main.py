import os
import uuid
import hashlib
import psycopg2
from typing import Optional, List
from datetime import datetime, timedelta, date

from fastapi import FastAPI, HTTPException, Depends, status, Header
from pydantic import BaseModel
from psycopg2.extras import RealDictCursor
from jose import jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware

# =============================================================================
# CONFIGURACIÓN GLOBAL
# =============================================================================

app = FastAPI(title="Scanneler Bypass API v3", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Render usará la variable de entorno DATABASE_URL
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = "Repit123.46123140DNI." # Cambia esto para máxima seguridad
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# =============================================================================
# MODELOS DE DATOS
# =============================================================================

class KeyGen(BaseModel):
    membresia: str
    duracion_dias: int
    cantidad: int

class UserRegister(BaseModel):
    key_code: str
    username: str
    password: str

class UserResponse(BaseModel):
    username: str
    role: str
    membresia: str
    vencimiento: Optional[date]
    hwid: str

# =============================================================================
# UTILIDADES
# =============================================================================

def get_db():
    """Retorna conexión a Supabase."""
    if not DATABASE_URL:
        raise Exception("DATABASE_URL no configurada en Render")
    return psycopg2.connect(DATABASE_URL)

def hash_pwd(p: str):
    return hashlib.sha256(p.encode()).hexdigest()

# =============================================================================
# ENDPOINTS PRINCIPALES
# =============================================================================

@app.get("/")
def health():
    return {"status": "Online", "v": "3.0.0"}

# --- LOGIN CON AUTO-REGISTRO DE HWID ---
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), x_hwid: Optional[str] = Header(None)):
    """Autentica y vincula el HWID si el usuario es nuevo."""
    db = get_db()
    try:
        cursor = db.cursor(cursor_factory=RealDictCursor)
        # Buscar usuario
        cursor.execute("SELECT * FROM bypass_users WHERE username = %s AND password = %s", 
                       (form_data.username, hash_pwd(form_data.password)))
        user = cursor.fetchone()
        
        if not user:
            raise HTTPException(401, "Usuario o clave incorrectos")

        # Lógica de HWID
        if user['hwid'] == 'NONE' and x_hwid:
            cursor.execute("UPDATE bypass_users SET hwid = %s WHERE id = %s", (x_hwid, user['id']))
            db.commit()
            user['hwid'] = x_hwid
        elif user['hwid'] != 'NONE' and user['hwid'] != x_hwid:
            raise HTTPException(403, "Hardware ID Mismatch: Acceso denegado")

        # Generar Token (Simplificado para tu lógica actual)
        return {
            "access_token": "session_active", 
            "token_type": "bearer", 
            "role": user['role'],
            "membresia": user['membresia']
        }
    finally:
        db.close()

# --- GENERAR LLAVES ---
@app.post("/keys/generate")
def generate_keys(payload: KeyGen):
    db = get_db()
    try:
        cursor = db.cursor()
        new_keys = []
        for _ in range(payload.cantidad):
            code = f"SCAN-{uuid.uuid4().hex[:12].upper()}"
            cursor.execute(
                "INSERT INTO bypass_keys (key_string, membresia, duracion_dias) VALUES (%s, %s, %s)",
                (code, payload.membresia, payload.duracion_dias)
            )
            new_keys.append(code)
        db.commit()
        return {"keys": new_keys}
    finally:
        db.close()

# --- REGISTRO POR LLAVE ---
@app.post("/keys/redeem")
def redeem(payload: UserRegister, x_hwid: Optional[str] = Header(None)):
    db = get_db()
    try:
        cursor = db.cursor(cursor_factory=RealDictCursor)
        # Validar key
        cursor.execute("SELECT * FROM bypass_keys WHERE key_string = %s AND is_used = False", (payload.key_code,))
        key_data = cursor.fetchone()
        if not key_data: raise HTTPException(400, "Key inválida o usada")

        # Calcular vencimiento
        expire = datetime.now().date() + timedelta(days=key_data['duracion_dias'])
        
        # Crear usuario
        cursor.execute(
            """INSERT INTO bypass_users (username, password, membresia, vencimiento, hwid) 
               VALUES (%s, %s, %s, %s, %s) RETURNING id""",
            (payload.username, hash_pwd(payload.password), key_data['membresia'], expire, x_hwid or 'NONE')
        )
        user_id = cursor.fetchone()['id']
        
        # Quemar key
        cursor.execute("UPDATE bypass_keys SET is_used = True, assigned_to = %s WHERE id = %s", (user_id, key_data['id']))
        db.commit()
        return {"msg": "Registrado con éxito"}
    finally:
        db.close()

# --- GESTIÓN ADMIN ---
@app.get("/admin/users", response_model=List[UserResponse])
def get_all_users():
    db = get_db()
    try:
        cursor = db.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT username, role, membresia, vencimiento, hwid FROM bypass_users")
        return cursor.fetchall()
    finally:
        db.close()

@app.put("/users/{username}/reset-hwid")
def reset_hwid(username: str):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute("UPDATE bypass_users SET hwid = 'NONE' WHERE username = %s", (username,))
        db.commit()
        return {"msg": "HWID Reseteado"}
    finally:
        db.close()
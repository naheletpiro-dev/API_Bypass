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

app = FastAPI(title="Scanneler Bypass API v3", version="3.5.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = "Repit123.46123140DNI." 
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

class UserUpdate(BaseModel):
    membresia: str
    duracion_dias: int

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
    if not DATABASE_URL:
        raise Exception("DATABASE_URL no configurada")
    try:
        return psycopg2.connect(
            DATABASE_URL, 
            connect_timeout=10,
            sslmode='require'
        )
    except Exception as e:
        print(f"[!] ERROR CRÍTICO DE RED: {e}")
        raise HTTPException(status_code=503, detail="Error de red con la base de datos")

def hash_pwd(p: str):
    return hashlib.sha256(p.encode()).hexdigest()

# =============================================================================
# ENDPOINTS PRINCIPALES
# =============================================================================

@app.get("/")
def health():
    return {"status": "Online", "v": "3.5.0"}

# --- LOGIN ---
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), x_hwid: Optional[str] = Header(None)):
    print(f"[AUTH] Intento de login para usuario: {form_data.username}")
    db = get_db()
    try:
        cursor = db.cursor(cursor_factory=RealDictCursor)
        hashed_input = hash_pwd(form_data.password).lower()
        
        cursor.execute("SELECT * FROM bypass_users WHERE username = %s AND password = %s", 
                       (form_data.username.strip(), hashed_input))
        user = cursor.fetchone()
        
        if not user:
            raise HTTPException(401, "Usuario o clave incorrectos")

        client_hwid = x_hwid if x_hwid else "NONE"
        
        if user['hwid'] == 'NONE' and client_hwid != 'NONE':
            cursor.execute("UPDATE bypass_users SET hwid = %s WHERE id = %s", (client_hwid, user['id']))
            db.commit()
        elif user['hwid'] != 'NONE' and user['hwid'] != client_hwid:
            raise HTTPException(403, "Hardware ID Mismatch")

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

# --- REGISTRO ---
@app.post("/keys/redeem")
def redeem(payload: UserRegister, x_hwid: Optional[str] = Header(None)):
    db = get_db()
    try:
        cursor = db.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM bypass_keys WHERE key_string = %s AND is_used = False", (payload.key_code,))
        key_data = cursor.fetchone()
        if not key_data: raise HTTPException(400, "Key inválida")

        expire = datetime.now().date() + timedelta(days=key_data['duracion_dias'])
        cursor.execute(
            """INSERT INTO bypass_users (username, password, membresia, vencimiento, hwid) 
               VALUES (%s, %s, %s, %s, %s) RETURNING id""",
            (payload.username, hash_pwd(payload.password), key_data['membresia'], expire, x_hwid or 'NONE')
        )
        user_id = cursor.fetchone()['id']
        cursor.execute("UPDATE bypass_keys SET is_used = True, assigned_to = %s WHERE id = %s", (user_id, key_data['id']))
        db.commit()
        return {"msg": "Éxito"}
    finally:
        db.close()

# =============================================================================
# GESTIÓN ADMIN (REQUERIDO PARA PANEL MODERNO)
# =============================================================================

@app.get("/admin/users", response_model=List[UserResponse])
def get_all_users():
    db = get_db()
    try:
        cursor = db.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT username, role, membresia, vencimiento, hwid FROM bypass_users ORDER BY created_at DESC")
        return cursor.fetchall()
    finally:
        db.close()

# --- ACTUALIZAR MEMBRESÍA ---
@app.put("/users/{username}")
def update_user_membership(username: str, payload: UserUpdate):
    db = get_db()
    try:
        cursor = db.cursor()
        new_expire = datetime.now().date() + timedelta(days=payload.duracion_dias)
        cursor.execute(
            "UPDATE bypass_users SET membresia = %s, vencimiento = %s WHERE username = %s",
            (payload.membresia, new_expire, username)
        )
        db.commit()
        return {"message": "Plan actualizado correctamente"}
    finally:
        db.close()

# --- RESET HWID ---
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

# --- ELIMINAR USUARIO (CON LIMPIEZA DE LLAVES) ---
@app.delete("/users/{username}")
def delete_user(username: str):
    db = get_db()
    try:
        cursor = db.cursor()
        # 1. Obtener ID
        cursor.execute("SELECT id FROM bypass_users WHERE username = %s", (username,))
        res = cursor.fetchone()
        if not res: raise HTTPException(404, "No encontrado")
        u_id = res[0]

        # 2. Desvincular llaves (Pone assigned_to en NULL para evitar error FK)
        cursor.execute("UPDATE bypass_keys SET assigned_to = NULL, is_used = False WHERE assigned_to = %s", (u_id,))
        
        # 3. Borrar usuario
        cursor.execute("DELETE FROM bypass_users WHERE id = %s", (u_id,))
        db.commit()
        return {"message": "Usuario eliminado y llaves liberadas"}
    finally:
        db.close()
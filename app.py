import os
import sqlite3
import uuid
import time
import base64
from pathlib import Path
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher



# This using pathlib to find the .env file that is in my directory to use that file
basedir = Path(__file__).resolve().parent
load_dotenv(os.path.join(basedir, ".env"))

NOT_MY_KEY = os.getenv("NOT_MY_KEY")


# This checks if that .env file is missing or not and if it is then it will provide a messaage
if NOT_MY_KEY is None:
    print(f"--- WARNING: NOT_MY_KEY not found in {basedir}/.env ---")
    print("--- Using a temporary fallback key for development ---")
    NOT_MY_KEY = "a_very_secret_32_byte_key_lookup" # Exactly 32 chars


app = Flask(__name__)
DB_NAME = "totally_not_my_private_keys.db"



def encrypt_key(private_key_text):
    # Ensure the key is exactly 32 bytes
   
    aad_key = NOT_MY_KEY.encode()
    aesgcm = AESGCM(aad_key)
    iv = os.urandom(12) 
    encrypted_bytes = aesgcm.encrypt(iv, private_key_text.encode(), None)
    return iv, encrypted_bytes

def decrypt_key(iv, encrypted_bytes):
    aad_key = NOT_MY_KEY.encode()
    aesgcm = AESGCM(aad_key)
    decrypted_bytes = aesgcm.decrypt(iv, encrypted_bytes, None)
    return decrypted_bytes.decode()

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER, 
        FOREIGN KEY(user_id) REFERENCES users(id))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        iv BLOB NOT NULL,
        exp INTEGER NOT NULL)''')
    conn.commit()
    conn.close()

def seed_one_key():
    """Generates an initial encrypted key if the table is empty."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM keys")
    if cursor.fetchone()[0] == 0:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        iv, encrypted_key = encrypt_key(pem)
        exp = int(time.time()) + 3600
        cursor.execute("INSERT INTO keys (key, iv, exp) VALUES (?, ?, ?)", (encrypted_key, iv, exp))
        conn.commit()
    conn.close()

# Routes to provide the HTTPs Methods

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    if not username or not email:
        return jsonify({"error": "Username and email are required"}), 400
    
    password = str(uuid.uuid4())
    ph = PasswordHasher()
    password_hash = ph.hash(password)
    
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                       (username, email, password_hash))
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return jsonify({"error": "User already exists"}), 400
        
    return jsonify({"password": password}), 201

import jwt  

@app.route('/auth', methods=['POST'])
def auth():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    request_ip = request.remote_addr

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    user_id, stored_hash = user
    ph = PasswordHasher()
    try:
        ph.verify(stored_hash, password)
    except Exception:
        return jsonify({"error": "Invalid credentials"}), 401

    # Provides the authentication request
    cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (request_ip, user_id))
    conn.commit()

    # Obtains the active key
    cursor.execute("SELECT key, iv, id FROM keys WHERE exp > strftime('%s', 'now') LIMIT 1")
    key_data = cursor.fetchone()
    if not key_data:
        conn.close()
        return jsonify({"error": "No active key found"}), 500
    
    encrypted_key, iv, key_id = key_data
    # Decrypts the private key
    decrypted_private_pem = decrypt_key(iv, encrypted_key)
    conn.close()

    
    headers = {
        "kid": str(key_id)
    }
    payload = {
        "username": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    
    
    # Signs the token that it is using for the private key
    token = jwt.encode(payload, decrypted_private_pem, algorithm="RS256", headers=headers)
    
    # This decodes the string
    if isinstance(token, bytes):
        token = token.decode('utf-8')

    return jsonify({"token": token})

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT key, iv, id FROM keys WHERE exp > strftime('%s', 'now')")
    rows = cursor.fetchall()
    conn.close()

    jwks_keys = []
    for row in rows:
        encrypted_key, iv, key_id = row
        pem_private_key = decrypt_key(iv, encrypted_key)
        priv_key_obj = serialization.load_pem_private_key(
            pem_private_key.encode(), password=None, backend=default_backend()
        )
        numbers = priv_key_obj.public_key().public_numbers()
        
        def to_base64url(n):
            return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, 'big')).decode().rstrip('=')

        jwks_keys.append({
            "alg": "RS256", "kty": "RSA", "use": "sig", "kid": str(key_id),
            "n": to_base64url(numbers.n), "e": to_base64url(numbers.e)
        })
    return jsonify({"keys": jwks_keys})

if __name__ == '__main__':
    init_db()
    seed_one_key() 
    print("Server starting on http://localhost:8080")
    app.run(port=8080)

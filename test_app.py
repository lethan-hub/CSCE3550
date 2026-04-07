import pytest
import requests
import time
import threading
import os

# This imports the components
from app import app, init_db, seed_one_key 

BASE_URL = "http://localhost:8080"

@pytest.fixture(scope="session", autouse=True)
def server():
    
    # This allows the testing to run smoothly
    if os.path.exists("test_jwks.db"):
        os.remove("test_jwks.db")
    
    
    # Starting the app for the testing
    with app.app_context():
        init_db()
        seed_one_key()
    
    # Runs flask
    thread = threading.Thread(target=app.run, kwargs={'port': 8080, 'debug': False, 'use_reloader': False})
    thread.daemon = True
    thread.start()
    
    time.sleep(1.5) # Give the server a moment to boot up
    yield
    

def test_jwks_endpoint():
    r = requests.get(f"{BASE_URL}/.well-known/jwks.json")
    assert r.status_code == 200
    assert "keys" in r.json()
    assert len(r.json()["keys"]) > 0

def test_full_user_flow():
    # Provides a timestap to make sure that the username is unique
    
    ts = int(time.time())
    username = f"coverage_user_{ts}"
    payload = {"username": username, "email": f"test_{ts}@example.com"}
    
    # Tests the Registration function
    reg_res = requests.post(f"{BASE_URL}/register", json=payload)
    assert reg_res.status_code == 201
    password = reg_res.json().get("password")

    # Tests the authentication function
    auth_payload = {"username": username, "password": password}
    auth_res = requests.post(f"{BASE_URL}/auth", json=auth_payload)
    assert auth_res.status_code == 200
    assert "token" in auth_res.json()

def test_auth_invalid_creds():
    # Ensures any errors to be fixed in the authenication function
    auth_res = requests.post(f"{BASE_URL}/auth", json={"username": "fake", "password": "wrong"})
    assert auth_res.status_code == 401

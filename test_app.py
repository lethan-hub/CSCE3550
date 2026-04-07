import pytest
import requests
import time
import threading
import os
# Import your actual app components
from app import app, init_db, seed_one_key 

BASE_URL = "http://localhost:8080"

@pytest.fixture(scope="session", autouse=True)
def server():
    # Setup: Ensure a clean state for testing
    if os.path.exists("test_jwks.db"):
        os.remove("test_jwks.db")
    
    # Initialize the app for the test session
    with app.app_context():
        init_db()
        seed_one_key()
    
    # Run the Flask app in a background thread
    # Setting 'use_reloader=False' is critical for pytest
    thread = threading.Thread(target=app.run, kwargs={'port': 8080, 'debug': False, 'use_reloader': False})
    thread.daemon = True
    thread.start()
    
    time.sleep(1.5) # Give the server a moment to boot up
    yield
    # Teardown: (Optional) remove test db after tests
    # os.remove("test_jwks.db")

def test_jwks_endpoint():
    r = requests.get(f"{BASE_URL}/.well-known/jwks.json")
    assert r.status_code == 200
    assert "keys" in r.json()
    assert len(r.json()["keys"]) > 0

def test_full_user_flow():
    # Use a timestamp to ensure the username is always unique
    ts = int(time.time())
    username = f"coverage_user_{ts}"
    payload = {"username": username, "email": f"test_{ts}@example.com"}
    
    # 1. Test Register (Covers the register function)
    reg_res = requests.post(f"{BASE_URL}/register", json=payload)
    assert reg_res.status_code == 201
    password = reg_res.json().get("password")

    # 2. Test Auth (Covers the auth function and JWT signing)
    auth_payload = {"username": username, "password": password}
    auth_res = requests.post(f"{BASE_URL}/auth", json=auth_payload)
    assert auth_res.status_code == 200
    assert "token" in auth_res.json()

def test_auth_invalid_creds():
    # Covers the error handling lines in your auth function
    auth_res = requests.post(f"{BASE_URL}/auth", json={"username": "fake", "password": "wrong"})
    assert auth_res.status_code == 401
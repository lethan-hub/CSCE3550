import requests
import time

# This is a standard test client for Project 2 (JWKS)
BASE_URL = "http://localhost:8080"

def run_tests():
    print(f"--- Starting Gradebot Tests against {BASE_URL} ---")
    
    # 1. Test JWKS Endpoint
    try:
        print("Checking /.well-known/jwks.json...")
        jwks_res = requests.get(f"{BASE_URL}/.well-known/jwks.json")
        if jwks_res.status_code == 200:
            print("PASS: JWKS endpoint is reachable.")
        else:
            print(f"FAIL: JWKS returned status {jwks_res.status_code}")
    except Exception as e:
        print(f"FAIL: Could not connect to server. Is it running? {e}")
        return

    # 2. Test Registration
    print("\nChecking /register...")
    user_data = {"username": "gradebot_user", "email": "bot@test.com"}
    reg_res = requests.post(f"{BASE_URL}/register", json=user_data)
    if reg_res.status_code == 201:
        password = reg_res.json().get("password")
        print(f"PASS: User registered. Password received: {password}")
    else:
        print(f"FAIL: Registration failed: {reg_res.text}")
        return

    # 3. Test Authentication
    print("\nChecking /auth...")
    auth_data = {"username": "gradebot_user", "password": password}
    auth_res = requests.post(f"{BASE_URL}/auth", json=auth_data)
    if auth_res.status_code == 200:
        token = auth_res.json().get("token")
        if token and token != "your_generated_jwt_here":
            print("PASS: Authentication successful. Real JWT received.")
        else:
            print("FAIL: Received placeholder token instead of real JWT.")
    else:
        print(f"FAIL: Auth failed: {auth_res.text}")

    print("\n--- Tests Complete ---")

if __name__ == "__main__":
    run_tests()
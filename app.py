import streamlit as st
import hashlib
import json
import os
import time
try:
    from cryptography.fernet import Fernet
except ModuleNotFoundError:
    st.error("Module 'cryptography' not found. Please install it using 'pip install cryptography'")
    Fernet = None
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === Configuration ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"  # In production, use os.urandom(16) to generate a random salt
LOCKOUT_DURATION = 60  # seconds
MAX_ATTEMPTS = 3
ITERATIONS = 100000

# Initialize session state
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
    st.session_state.failed_attempts = 0
    st.session_state.lockout_time = 0

# === Helper Functions ===
def load_data():
    """Load encrypted data from file"""
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        return {}
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return {}

def save_data(data):
    """Save data to file with error handling"""
    try:
        with open(DATA_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        st.error(f"Error saving data: {e}")

def generate_key(passkey):
    """Generate encryption key from passkey"""
    key = pbkdf2_hmac(
        "sha256",
        passkey.encode(),
        SALT,
        ITERATIONS,
        dklen=32  # Fernet needs 32 bytes
    )
    return urlsafe_b64encode(key)  # Fernet requires URL-safe base64

def hash_password(password):
    """Create secure password hash"""
    return pbkdf2_hmac(
        "sha256",
        password.encode(),
        SALT,
        ITERATIONS
    ).hex()

# === Cryptography Functions ===
def encrypt_text(text, key):
    """Encrypt text using Fernet"""
    try:
        cipher = Fernet(generate_key(key))
        return cipher.encrypt(text.encode()).decode()
    except Exception as e:
        st.error(f"Encryption failed: {e}")
        return None

def decrypt_text(encrypted_text, key):
    """Decrypt text using Fernet"""
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None  # Return None for any decryption failure

# Load data at startup
stored_data = load_data()

# === UI Components ===
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("Welcome to the 🔒 Data Encryption System")
    st.markdown("""
    This system provides secure data storage and retrieval with:
    - User authentication
    - Passkey-based encryption
    - Brute-force protection
    - No external databases
    
    ### Features:
    1. **Register** - Create a new user account
    2. **Login** - Access your encrypted data
    3. **Store Data** - Encrypt and save sensitive information
    4. **Retrieve Data** - Decrypt your stored data with your passkey
    """)

# === User Registration ===
elif choice == "Register":
    st.subheader("🖊 Register New User")
    username = st.text_input("Choose Username").strip()
    password = st.text_input("Choose Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    
    if st.button("Register"):
        if not username or not password:
            st.error("Username and password are required")
        elif len(password) < 8:
            st.error("Password must be at least 8 characters")
        elif password != confirm_password:
            st.error("Passwords do not match")
        elif username in stored_data:
            st.warning("Username already exists")
        else:
            stored_data[username] = {
                "password": hash_password(password),
                "data": []
            }
            save_data(stored_data)
            st.success("✅ User registered successfully")
            st.balloons()

# === User Login ===
elif choice == "Login":
    st.subheader("🔑 User Login")
    
    # Check if user is locked out
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⌛ Account locked. Please wait {remaining} seconds.")
        st.stop()
    
    username = st.text_input("Username").strip()
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if not username or not password:
            st.error("Both fields are required")
        elif username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome {username}!")
            time.sleep(1)
            st.rerun()  # Refresh to update navigation
        else:
            st.session_state.failed_attempts += 1
            remaining_attempts = MAX_ATTEMPTS - st.session_state.failed_attempts
            
            if remaining_attempts > 0:
                st.error(f"❌ Invalid credentials! {remaining_attempts} attempts remaining")
            else:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🛑 Too many failed attempts. Account locked for 60 seconds.")
                st.stop()

# === Store Data ===
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first")
    else:
        st.subheader("📦 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption passkey", type="password")
        confirm_passkey = st.text_input("Confirm passkey", type="password")
        
        if st.button("Encrypt and Save"):
            if not data:
                st.error("Data field is required")
            elif not passkey:
                st.error("Passkey is required")
            elif passkey != confirm_passkey:
                st.error("Passkeys do not match")
            else:
                encrypted = encrypt_text(data, passkey)
                if encrypted:
                    stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                    save_data(stored_data)
                    st.success("✅ Data encrypted and saved successfully!")
                    st.balloons()

# === Retrieve Data ===
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first")
    else:
        st.subheader("🔍 Retrieve Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])
        
        if not user_data:
            st.info("No encrypted data found")
        else:
            st.write(f"Found {len(user_data)} encrypted entries:")
            
            # Display encrypted items with index
            selected_index = st.selectbox(
                "Select data to decrypt",
                range(len(user_data)),
                format_func=lambda x: f"Entry #{x+1}"
            )
            
            encrypted_data = user_data[selected_index]
            st.code(encrypted_data, language="text")
            
            passkey = st.text_input("Enter passkey to decrypt", type="password")
            
            if st.button("Decrypt"):
                decrypted = decrypt_text(encrypted_data, passkey)
                if decrypted:
                    st.success("✅ Decryption successful!")
                    st.text_area("Decrypted Data", decrypted, height=200)
                else:
                    st.error("❌ Decryption failed - incorrect passkey or corrupted data")

# === Logout ===
elif choice == "Logout":
    if st.session_state.authenticated_user:
        st.session_state.authenticated_user = None
        st.success("Logged out successfully")
        time.sleep(1)
        st.experimental_rerun()
    else:
        st.warning("You're not currently logged in")

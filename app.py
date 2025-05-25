import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import time
import uuid
import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# File path for storing encrypted data
DATA_FILE = "encrypted_data.json"

# Security constants
LOCKOUT_DURATION = 300  # 5 minutes in seconds
SALT = b'secure_salt_123'  # In production, use a unique salt per user
PBKDF2_ITERATIONS = 100000

# Initialize session state for failed attempts
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0
if 'is_authorized' not in st.session_state:
    st.session_state.is_authorized = True
if 'max_attempts' not in st.session_state:
    st.session_state.max_attempts = 3
if 'lockout_until' not in st.session_state:
    st.session_state.lockout_until = 0

# Generate a key (this should be stored securely in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Function to load data from JSON file
def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            st.error("Error reading data file. Starting with empty storage.")
            return {}
    return {}

# Function to save data to JSON file
def save_data(data):
    try:
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        st.error(f"Error saving data: {str(e)}")

# Load stored data from file
stored_data = load_data()

# Function to hash passkey using PBKDF2
def hash_passkey(passkey):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(passkey.encode())
    return base64.b64encode(key).decode()

# Function to encrypt data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    current_time = time.time()
    
    # Check if user is in lockout period
    if current_time < st.session_state.lockout_until:
        remaining_lockout = int(st.session_state.lockout_until - current_time)
        st.error(f"🔒 Account is locked. Please try again in {remaining_lockout} seconds.")
        return None
    
    # Check if we need to reset failed attempts (after 30 minutes)
    if current_time - st.session_state.last_attempt_time > 1800:  # 30 minutes
        st.session_state.failed_attempts = 0
    
    hashed_passkey = hash_passkey(passkey)

    # Search through stored data for matching entry
    for entry_id, entry_data in stored_data.items():
        if entry_data["encrypted_text"] == encrypted_text and entry_data["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            st.session_state.last_attempt_time = current_time
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    st.session_state.last_attempt_time = current_time
    
    # Apply lockout if max attempts reached
    if st.session_state.failed_attempts >= st.session_state.max_attempts:
        st.session_state.lockout_until = current_time + LOCKOUT_DURATION
        st.session_state.is_authorized = False
    
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Display current failed attempts if any
if st.session_state.failed_attempts > 0:
    st.warning(f"⚠️ Failed attempts: {st.session_state.failed_attempts}/{st.session_state.max_attempts}")

# Display lockout status if applicable
current_time = time.time()
if current_time < st.session_state.lockout_until:
    remaining_lockout = int(st.session_state.lockout_until - current_time)
    st.error(f"🔒 Account is locked. Please try again in {remaining_lockout} seconds.")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Check authorization status
if not st.session_state.is_authorized and choice != "Login":
    st.warning("🔒 Please reauthorize to continue!")
    st.experimental_rerun()

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            # Generate unique entry ID
            entry_id = f"entry_{uuid.uuid4().hex[:8]}"
            
            # Hash the passkey
            hashed_passkey = hash_passkey(passkey)
            
            # Encrypt the data
            encrypted_text = encrypt_data(user_data, passkey)
            
            # Store with proper structure
            stored_data[entry_id] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            
            # Save to file
            save_data(stored_data)
            
            st.success(f"✅ Data stored securely! Your entry ID is: {entry_id}")
            st.info("Please save this entry ID for future reference.")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    entry_id = st.text_input("Enter Entry ID:")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey and entry_id:
            # Verify entry exists
            if entry_id not in stored_data:
                st.error("❌ Entry ID not found!")
            else:
                decrypted_text = decrypt_data(encrypted_text, passkey)

                if decrypted_text:
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:
                    remaining_attempts = st.session_state.max_attempts - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining_attempts}")

                    if st.session_state.failed_attempts >= st.session_state.max_attempts:
                        st.session_state.is_authorized = False
                        st.error("🔒 Maximum attempts reached! Please reauthorize.")
                        st.experimental_rerun()
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded for demo, replace with proper auth
            st.session_state.failed_attempts = 0
            st.session_state.is_authorized = True
            st.success("✅ Reauthorized successfully! Redirecting to Home...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")

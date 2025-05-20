import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# ==== Configuration ====
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60  # seconds

# ==== Session state initialization ====
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
if "users" not in st.session_state:
    st.session_state.users = []

# ==== Helper Functions ====
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_data(data, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(data.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# ==== Load existing data ====
stored_data = load_data()

# ==== UI ====
st.title("🔐 Secure Data Encryption System")
menu = ["🏠 Home", "📝 Register", "🔑 Login", "💾 Store Data", "📂 Retrieve Data"]
choice = st.sidebar.selectbox("📌 Navigation", menu)

# ==== Home ====
if choice == "🏠 Home":
    st.subheader("🔐 Welcome to Secure Data Encryption System Using Streamlit!")
    st.markdown("💡 A Streamlit-based secure data storage and retrieval system where:\n"
                "- 🔑 Users store data with a unique passkey\n"
                "- 🔓 Data can only be decrypted with correct passkey\n"
                "- ⛔ Multiple failed login attempts result in a lockout\n"
                "- 🧠 All data is stored securely in a JSON file")

# ==== Register ====
elif choice == "📝 Register":
    st.subheader("🆕 Register New User")
    username = st.text_input("👤 Choose Username")
    password = st.text_input("🔐 Choose Password", type="password")

    if st.button("✅ Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ User already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []  # ✅ FIXED: Initialize with a list
                }
                save_data(stored_data)
                st.session_state.users.append(username)
                st.success("🎉 User registered successfully!")
        else:
            st.error("❌ Please enter a valid username and password.")

# ==== Login ====
elif choice == "🔑 Login":
    st.subheader("🔐 User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"🚫 Too many failed attempts. Try again in {remaining} seconds.")
        st.stop()

    username = st.text_input("👤 Username")
    password = st.text_input("🔐 Password", type="password")

    if st.button("🔓 Login"):
        if username in stored_data:
            stored_password = stored_data[username]["password"]
            if stored_password == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f"✅ Login Successful. Welcome {username}!")
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect password. Attempts left: {remaining}")
        else:
            st.error("❌ Username not found.")

        if st.session_state.failed_attempts >= 3:
            st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
            st.warning("⛔ Too many failed attempts. Locked for 60 seconds.")
            st.stop()

# ==== Store Data ====
elif choice == "💾 Store Data":
    st.subheader("💾 Store Encrypted Data")

    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first.")
    else:
        data = st.text_area("📄 Enter data to encrypt")
        passkey = st.text_input("🔑 Encryption Key (Passphrase)", type="password")

        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_data(data, passkey)
                username = st.session_state.authenticated_user
                stored_data[username]["data"].append(encrypted)  # ✅ Append to list
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully!")
            else:
                st.error("❌ All fields are required.")

# ==== Retrieve Data ====
elif choice == "📂 Retrieve Data":
    st.subheader("📂 Retrieve Encrypted Data")

    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first.")
    else:
        username = st.session_state.authenticated_user
        user_data = stored_data.get(username, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No data found.")
        else:
            st.write("🔐 Encrypted Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_area("🔐 Enter Encrypted Text to Decrypt")
            passkey = st.text_input("🔑 Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"✅ Decrypted text: {result}")
                else:
                    st.error("❌ Decryption failed. Invalid key or text.")

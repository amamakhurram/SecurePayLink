# app.py

import streamlit as st
import sqlite3
import bcrypt
import os
import re
import secrets
import datetime
import base64
from cryptography.fernet import Fernet
from email_validator import validate_email, EmailNotValidError

# -------------------------
# Configuration & init
# -------------------------
APP_NAME = "SecurePayLink"
DB_PATH = "database.db"
KEY_FILE = "secret.key"
UPLOAD_DIR = "uploads"
SESSION_TIMEOUT_SECONDS = 300  # 5 minutes idle timeout

os.makedirs(UPLOAD_DIR, exist_ok=True)

# -------------------------
# Encryption key
# -------------------------
def get_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return key

FERNET = Fernet(get_or_create_key())

# -------------------------
# DB helpers
# -------------------------
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        profile_pic TEXT
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        creator TEXT NOT NULL,
        recipient TEXT,
        amount REAL NOT NULL,
        message_enc TEXT,
        token TEXT UNIQUE NOT NULL,
        expiry_ts INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT NOT NULL,
        timestamp INTEGER NOT NULL
    );
    """)
    conn.commit()
    conn.close()

init_db()

# -------------------------
# Utility functions
# -------------------------
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

def check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed)

def password_ok(password: str):
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[^\w\s]", password):
        return False, "Password must contain at least one symbol."
    return True, ""

def log_action(username: str, action: str):
    conn = get_conn()
    cur = conn.cursor()
    ts = int(datetime.datetime.utcnow().timestamp())
    cur.execute("INSERT INTO logs (username, action, timestamp) VALUES (?, ?, ?);", (username, action, ts))
    conn.commit()
    conn.close()

def generate_token(length=22):
    return secrets.token_urlsafe(length)[:length]

def encrypt_message(message: str) -> str:
    token = FERNET.encrypt(message.encode("utf-8"))
    return token.decode("utf-8")

def decrypt_message(token_str: str) -> str:
    try:
        return FERNET.decrypt(token_str.encode("utf-8")).decode("utf-8")
    except Exception:
        return "[decryption error]"

def validate_amount(amount_str: str):
    try:
        v = float(amount_str)
        if v <= 0:
            return False, "Amount must be positive."
        return True, v
    except Exception:
        return False, "Invalid amount format."

def validate_filename(fn: str):
    allowed = (".jpg", ".jpeg", ".png")
    return any(fn.lower().endswith(ext) for ext in allowed)

def is_logged_in():
    return "username" in st.session_state and st.session_state.get("username")

def update_activity():
    st.session_state["last_activity"] = datetime.datetime.utcnow().timestamp()

def check_session_timeout():
    last = st.session_state.get("last_activity", None)
    if last and datetime.datetime.utcnow().timestamp() - last > SESSION_TIMEOUT_SECONDS:
        uname = st.session_state.get("username")
        if uname:
            log_action(uname, "session_timeout_logout")
        for k in ("username", "last_activity"):
            if k in st.session_state:
                del st.session_state[k]
        st.warning("Session timed out due to inactivity. Please login again.")
        return True
    return False
# -------------------------

# --- TEMP TEST: intentional error (REMOVE BEFORE FINAL SUBMISSION) ---
# if st.sidebar.checkbox("Show dev test controls"):
    # st.markdown("**Dev testing:** force an exception")
    # if st.button("Trigger divide-by-zero"):
        # Intentionally cause an exception
        # 1 / 0
# -------------------------------------------------------------------

# Auth functions
# -------------------------
def register_user(username, email, password, profile_pic_path=None):
    try:
        v = validate_email(email)
        email = v.email
    except EmailNotValidError as e:
        return False, f"Invalid email: {str(e)}"
    ok, msg = password_ok(password)
    if not ok:
        return False, msg
    hashed = hash_password(password)
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, email, password, profile_pic) VALUES (?, ?, ?, ?);",
                    (username, email, hashed, profile_pic_path))
        conn.commit()
        log_action(username, "registered")
        return True, "Registration successful."
    except sqlite3.IntegrityError as e:
        if "username" in str(e).lower():
            return False, "Username already taken."
        if "email" in str(e).lower():
            return False, "Email already registered."
        return False, "Database error: " + str(e)
    finally:
        conn.close()

def login_user(username, password):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE username = ?;", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False, "Invalid username or password."
    stored = row["password"]
    stored_b = stored.encode("utf-8") if isinstance(stored, str) else stored
    if check_password(password, stored_b):
        st.session_state["username"] = username
        update_activity()
        log_action(username, "login")
        return True, "Login successful."
    log_action(username, "failed_login")
    return False, "Invalid username or password."

def logout_user():
    uname = st.session_state.get("username")
    if uname:
        log_action(uname, "logout")
    for k in ("username", "last_activity"):
        st.session_state.pop(k, None)

# -------------------------
# Payment functions
# -------------------------
def create_payment(creator, amount, message, expiry_minutes=10, recipient=None):
    token = generate_token(22)
    expiry_ts = int((datetime.datetime.utcnow() + datetime.timedelta(minutes=expiry_minutes)).timestamp())
    msg_enc = encrypt_message(message)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""INSERT INTO payments (creator, recipient, amount, message_enc, token, expiry_ts, status)
                   VALUES (?, ?, ?, ?, ?, ?, 'pending');""",
                (creator, recipient, amount, msg_enc, token, expiry_ts))
    conn.commit()
    conn.close()
    log_action(creator, f"created_payment_{token}")
    return token

def get_payment_by_token(token):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM payments WHERE token = ?;", (token,))
    row = cur.fetchone()
    conn.close()
    return row

def mark_payment_paid(token, username):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE payments SET status = 'paid', recipient = ? WHERE token = ?;", (username, token))
    conn.commit()
    conn.close()
    log_action(username, f"paid_{token}")

def list_user_payments(username):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM payments WHERE creator = ? ORDER BY id DESC;", (username,))
    rows = cur.fetchall()
    conn.close()
    return rows

def list_all_logs(limit=200):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?;", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows

# -------------------------
# Streamlit UI
# -------------------------
st.set_page_config(page_title=APP_NAME, layout="wide")
st.title(APP_NAME)
st.caption("Mini FinTech app for secure pay-link creation — CY4053 assignment demo")

if "last_activity" not in st.session_state:
    st.session_state["last_activity"] = datetime.datetime.utcnow().timestamp()
if "username" not in st.session_state:
    st.session_state["username"] = None

if is_logged_in():
    if check_session_timeout():
        pass
    else:
        update_activity()

# Sidebar
menu = st.sidebar.selectbox("Menu", ["Home", "Register", "Login", "Dashboard", "Create Payment Link", "View Payment (token)", "Profile", "Audit Logs"])

# Home
if menu == "Home":
    st.write("Welcome! Use the sidebar to Register, Login, and create payment links.")
    if is_logged_in():
        st.success(f"Logged in as {st.session_state['username']}")
        if st.button("Logout"):
            logout_user()
            st.rerun()

# Register
if menu == "Register":
    st.header("Register")
    with st.form("register_form"):
        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        password2 = st.text_input("Confirm Password", type="password")
        profile_pic = st.file_uploader("Profile Picture (optional, .jpg/.png)", type=["png", "jpg", "jpeg"])
        submitted = st.form_submit_button("Create Account")
    if submitted:
        if not username or not email or not password or not password2:
            st.error("Please fill all required fields.")
        elif password != password2:
            st.error("Passwords do not match.")
        else:
            pic_path = None
            if profile_pic:
                if not validate_filename(profile_pic.name):
                    st.error("Profile picture must be .jpg or .png")
                else:
                    safe_fn = secrets.token_hex(8) + "_" + profile_pic.name
                    save_path = os.path.join(UPLOAD_DIR, safe_fn)
                    with open(save_path, "wb") as f:
                        f.write(profile_pic.getbuffer())
                    pic_path = save_path
            ok, msg = register_user(username.strip(), email.strip(), password, pic_path)
            if ok:
                st.success(msg)
                st.session_state["redirect_to_login"] = True
                st.toast("Redirecting to Login...", icon="🔁")
                st.rerun()
            else:
                st.error(msg)

# Login
if menu == "Login":
    st.header("Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
    if submitted:
        if not username or not password:
            st.error("Please provide username and password.")
        else:
            ok, msg = login_user(username.strip(), password)
            if ok:
                st.success(msg)
                st.session_state["redirect_to_dashboard"] = True
                st.toast("Redirecting to Dashboard...", icon="✅")
                st.rerun()
            else:
                st.error(msg)

# Dashboard
if menu == "Dashboard":
    st.header("Dashboard")
    if not is_logged_in():
        st.warning("You need to login to view the dashboard.")
    else:
        uname = st.session_state["username"]
        st.success(f"Welcome, {uname}")
        if st.button("Logout"):
            logout_user()
            st.rerun()
        st.subheader("Your Payment Links")
        rows = list_user_payments(uname)
        if not rows:
            st.info("You have not created any payment links yet.")
        else:
            for r in rows:
                expiry_dt = datetime.datetime.utcfromtimestamp(r["expiry_ts"])
                msg = decrypt_message(r["message_enc"]) if r["message_enc"] else ""
                st.markdown(f"**Token:** `{r['token']}` | **Amount:** {r['amount']} | **Status:** {r['status']} | Expires (UTC): {expiry_dt}")
                st.caption(f"Message: {msg}")

# Create Payment
if menu == "Create Payment Link":
    st.header("Create Temporary Payment Link")
    if not is_logged_in():
        st.warning("Login required.")
    else:
        with st.form("create_payment"):
            amount = st.text_input("Amount (e.g., 500.00)")
            message = st.text_area("Message (max 500 chars)", "", max_chars=1000)
            expiry = st.number_input("Expiry (minutes)", 1, 1440, 10)
            recipient = st.text_input("Recipient (optional username)")
            submitted = st.form_submit_button("Create Link")
        if submitted:
            ok, val = validate_amount(amount)
            if not ok:
                st.error(val)
            elif not message.strip():
                st.error("Message cannot be empty.")
            else:
                token = create_payment(st.session_state["username"], val, message.strip(), expiry, recipient.strip() if recipient else None)
                st.success("Payment link created successfully!")
                st.write(f"**Token:** `{token}`")
                st.write(f"Example: `http://localhost:8501/?token={token}`")

# View Payment
if menu == "View Payment (token)":
    st.header("View / Complete Payment by Token")
    token_in = st.text_input("Enter Payment Token")
    qparams = st.query_params
    if "token" in qparams:
        token_in = qparams.get("token")[0]
    if token_in:
        r = get_payment_by_token(token_in.strip())
        if not r:
            st.error("Invalid token.")
        else:
            expiry_dt = datetime.datetime.utcfromtimestamp(r["expiry_ts"])
            st.markdown(f"**Creator:** {r['creator']} | **Amount:** {r['amount']} | **Status:** {r['status']} | Expires: {expiry_dt}")
            msg = decrypt_message(r["message_enc"]) if r["message_enc"] else ""
            st.write("Message:", msg)
            if int(datetime.datetime.utcnow().timestamp()) > r["expiry_ts"]:
                st.error("This payment link has expired.")
            else:
                if is_logged_in() and st.button("Simulate Pay Now"):
                    mark_payment_paid(token_in.strip(), st.session_state["username"])
                    st.success("Payment marked as paid.")
                    st.rerun()

# Profile
if menu == "Profile":
    st.header("Profile")
    if not is_logged_in():
        st.warning("Login required.")
    else:
        uname = st.session_state["username"]
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT username, email, profile_pic FROM users WHERE username = ?;", (uname,))
        row = cur.fetchone()
        conn.close()
        if row:
            st.write("Username:", row["username"])
            st.write("Email:", row["email"])
            if row["profile_pic"] and os.path.exists(row["profile_pic"]):
                st.image(row["profile_pic"], width=120)

# Audit Logs
if menu == "Audit Logs":
    if not is_logged_in():
        st.warning("Please login to view audit logs.")
    else:
        st.header("Audit Logs (recent)")
        rows = list_all_logs(200)
        if not rows:
            st.info("No logs yet.")
        else:
            for r in rows:
                ts = datetime.datetime.utcfromtimestamp(r["timestamp"]).strftime("%Y-%m-%d %H:%M:%S UTC")
                st.write(f"{ts} — {r['username']} — {r['action']}")

# Redirects
if "redirect_to_login" in st.session_state:
    st.session_state.pop("redirect_to_login")
    menu = "Login"
    st.rerun()

if "redirect_to_dashboard" in st.session_state:
    st.session_state.pop("redirect_to_dashboard")
    menu = "Dashboard"
    st.rerun()

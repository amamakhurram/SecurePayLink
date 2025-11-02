# SecurePayLink — Mini FinTech App (CY4053 Secure Application)

> A secure FinTech web application built with **Streamlit** and **SQLite**, designed to demonstrate secure coding, encryption, and defensive programming techniques.  
> Developed as part of **CY4053 — Secure Application Development (Assignment 2)**.

---

##  Features
 User Registration & Login (with bcrypt password hashing)  
 Password strength enforcement (uppercase, number, symbol)  
Email validation  
Secure session management with auto logout (5 min idle timeout)  
AES encryption for payment messages using `cryptography.Fernet`  
Temporary paylink tokens with expiry  
Profile picture validation (.jpg/.png only)  
Full audit logging for every user action  
SQL Injection & XSS prevention  
Detailed manual test documentation (included as `.docx`)

---

## Tech Stack

| Component | Technology |
|------------|-------------|
| **Frontend** | Streamlit |
| **Backend** | Python 3.x |
| **Database** | SQLite3 |
| **Encryption** | AES (via `cryptography.Fernet`) |
| **Hashing** | bcrypt |
| **Validation** | email-validator |
| **IDE** | VS Code |

---

##  Installation & Setup

### Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/SecurePayLink.git
cd SecurePayLink
```
### Create a Virtual Environment
```bash
python -m venv venv
venv\Scripts\activate     # (on Windows)
# or
source venv/bin/activate  # (on macOS/Linux)
```
### Install Requirements
```bash
pip install -r requirements.txt
```

### Run the App
```streamlit run app.py
```
### Requirements
```bash
streamlit
bcrypt
cryptography
email-validator
sqlite3-binary
```

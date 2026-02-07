## 🔐 SecureText ECC
Zero-Trust Secure Messaging with ECC Encryption

A security-first Django application demonstrating modern cryptography, zero-trust access control, and non-repudiable audit logging.

## 🚀 Why This Project Exists (Read This First)

Most so‑called “secure messaging” projects fall short in critical ways:
- They encrypt data but still leave gaps ❌
- They trust administrators blindly, without checks ❌
- They allow audit logs to be edited or deleted, erasing accountability ❌

SecureText ECC is different.
- This project was built to answer one uncompromising question:
- “How do you design a system where even administrators cannot act without accountability?”

🔑 What Makes It Unique
- Zero‑Trust by Design: No user — **not even admins — is trusted by default.**
- Immutable Audit Trails: Every sensitive action is logged permanently, with no option to edit or delete.
- Justification Required: Admins must provide a reason before decrypting, ensuring intent is explicit.
- Defense‑in‑Depth: Copying, printing, and screenshots are deterred; exposure is temporary and traceable.

## 🧠 What Makes This Project Different
- ✅ Plaintext is never stored
- ✅ Admins must re‑authenticate before decryption
- ✅ Every decryption is immutably audited
- ✅ Audit logs cannot be edited or deleted
- ✅ Strong cryptography: ECC + AES‑GCM
- ✅ Login abuse is rate‑limited and controlled
This isn’t just another CRUD app — it’s a security system built for accountability.

🏗️ High‑Level Architecture (Skimmable)
User
  ↓
ECC Key Exchange
  ↓
AES‑GCM Encryption
  ↓
Encrypted Database
  ↓
(Admin Access)
   → Password Re‑Authentication
   → Reason for Access
   → Immutable Audit Log

## 🔒 Cryptography Overview (Simple First)

| Component          | Purpose                          |
|--------------------|----------------------------------|
| **ECC**            | Secure key exchange              |
| **AES‑GCM**        | Authenticated encryption         |
| **Nonce + Salt**   | Prevent replay & key reuse       |
| **In‑memory only** | No plaintext persistence         |

➡️ Plaintext exists only in RAM, only temporarily, and only after explicit admin approval.

## 👤 Authentication & Abuse Protection

### Login Security
- Failed attempts tracked per session  
- Cooldown after **3 failures**  
- Redirect to registration after **5 failures**  
- Live countdown timer during lockout  
- Inputs disabled during cooldown  

**Why this matters**  
Prevents:  
- Brute force attacks  
- Credential stuffing  
- Silent login failures  

---

## 🧾 Audit Logging (This Is the Important Part)

### Each admin decryption logs:
- **Who** accessed the data  
- **When** it happened  
- **Which** submission was decrypted  
- **Why** access was required  
- **Where** (IP – contextual, not trusted)  

### Audit Guarantees
- Append‑only  
- View‑only in Django admin  
- Cannot be edited ❌  
- Cannot be deleted ❌  

➡️ This ensures **non‑repudiation** and full accountability.

## 🛑 Admin Decryption Safeguards

When plaintext is shown:
- 🚫 Copy disabled  
- 🚫 Text selection disabled  
- 🚫 Print disabled  
- 🌫️ Tab‑switch blur  
- ⏳ Time‑limited visibility  
- 🧾 Action permanently logged  

## 🧪 Threat Model 

| Threat               | Mitigation                     |
|----------------------|--------------------------------|
| **DB breach**        | Encrypted ciphertext only      |
| **Malicious admin**  | Re‑auth + immutable logs       |
| **Password attacks** | Cooldown + lockout             |
| **Insider denial**   | Non‑repudiation                |
| **UI leaks**         | Copy / print / blur defenses   |



## 🛠 Tech Stack

**Backend**
- Django 5.x  
- Python 3.12+  

**Cryptography**
- ECC     (Elliptic Curve Cryptography)  
- AES‑GCM (Authenticated Encryption)  

**Frontend**
- Django Templates  
- Bootstrap 5  
- Vanilla JavaScript (no heavy frameworks)  
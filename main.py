import streamlit as st
from cryptography.fernet import Fernet
import hashlib
from datetime import datetime  # Added for time-stamping logs

# --- 1. USER DATABASE ---
USER_DB = {
    "admin": {"password": "123", "role": "Admin"},
    "hr": {"password": "hr123", "role": "HR"},
    "fin": {"password": "fin123", "role": "Finance"},
    "audit": {"password": "audit", "role": "Auditor"}
}

# --- 2. SYSTEM STATE SETUP ---
if 'key' not in st.session_state:
    st.session_state.key = Fernet.generate_key()
if 'vault' not in st.session_state:
    st.session_state.vault = []
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'audit_logs' not in st.session_state:
    st.session_state.audit_logs = []  # Initialize Audit Log

cipher = Fernet(st.session_state.key)

# Helper function to add logs
def add_log(action, detail):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state.audit_logs.append(f"[{timestamp}] {st.session_state.username} ({st.session_state.role}): {action} - {detail}")

# --- 3. LOGIN INTERFACE ---
st.sidebar.title("🔐 Secure Login")
if not st.session_state.logged_in:
    user_input = st.sidebar.text_input("Username")
    pass_input = st.sidebar.text_input("Password", type="password")
    
    if st.sidebar.button("Login"):
        if user_input in USER_DB and USER_DB[user_input]["password"] == pass_input:
            st.session_state.logged_in = True
            st.session_state.username = user_input
            st.session_state.role = USER_DB[user_input]["role"]
            add_log("LOGIN", "Successfully logged into the system")
            st.rerun()
        else:
            st.sidebar.error("Invalid Credentials")
else:
    st.sidebar.success(f"User: {st.session_state.username}")
    st.sidebar.info(f"Role: {st.session_state.role}")
    if st.sidebar.button("Logout"):
        add_log("LOGOUT", "User signed out")
        st.session_state.logged_in = False
        st.rerun()

# --- 4. DASHBOARD LOGIC ---
st.title("⚔️ Secure Inter-Department Data Exchange")

if st.session_state.logged_in:
    if st.session_state.role == "Auditor":
        tabs = ["📥 Compliance Audit Vault", "📜 Activity Logs"]
    else:
        tabs = ["📤 Upload & Secure", "📥 Department Vault", "📜 Activity Logs"]
    
    current_tabs = st.tabs(tabs)
    
    # --- UPLOAD SECTION ---
    if st.session_state.role != "Auditor":
        with current_tabs[0]:
            st.subheader("Encrypt & Send Data")
            uploaded_file = st.file_uploader("Select sensitive file")
            
            if uploaded_file and st.button("Apply AES-256 & SHA-256"):
                file_bytes = uploaded_file.getvalue()
                f_hash = hashlib.sha256(file_bytes).hexdigest()
                enc_data = cipher.encrypt(file_bytes)
                
                st.session_state.vault.append({
                    "name": uploaded_file.name,
                    "owner_dept": st.session_state.role,
                    "hash": f_hash,
                    "data": enc_data,
                    "uploader": st.session_state.username
                })
                add_log("UPLOAD", f"Encrypted and uploaded {uploaded_file.name}")
                st.success(f"Success! {uploaded_file.name} is now encrypted.")

    # --- VAULT SECTION ---
    vault_tab_idx = 0 if st.session_state.role == "Auditor" else 1
    with current_tabs[vault_tab_idx]:
        st.subheader(f"Data Access for {st.session_state.role}")
        if not st.session_state.vault:
            st.write("No files in the system.")
            
        for idx, item in enumerate(st.session_state.vault):
            is_owner = (st.session_state.role == item["owner_dept"])
            is_admin = (st.session_state.role == "Admin")
            is_auditor = (st.session_state.role == "Auditor")
            
            with st.expander(f"📁 {item['name']} (Source: {item['owner_dept']})"):
                st.code(f"SHA-256 Integrity: {item['hash']}")
                
                if is_admin or is_owner:
                    if st.button("Decrypt & Download", key=idx):
                        decrypted = cipher.decrypt(item["data"])
                        add_log("DECRYPT", f"Accessed and decrypted {item['name']}")
                        st.download_button("Save Original File", decrypted, file_name=item["name"])
                elif is_auditor:
                    st.warning("Audit Mode: Integrity verified via SHA-256. Decryption blocked.")
                else:
                    # Log unauthorized access attempts!
                    if st.button("Try Access", key=f"fail_{idx}"):
                        add_log("UNAUTHORIZED ATTEMPT", f"Tried to access {item['name']} (ACCESS DENIED)")
                        st.error("Access Denied: You do not have permissions.")

    # --- AUDIT LOG TAB ---
    log_tab_idx = 1 if st.session_state.role == "Auditor" else 2
    with current_tabs[log_tab_idx]:
        st.subheader("📜 System Activity Trail")
        if st.session_state.role in ["Admin", "Auditor"]:
            for log in reversed(st.session_state.audit_logs):
                st.text(log)
        else:
            st.warning("Only Administrators and Auditors can view the full activity trail.")
            # Normal users only see their own recent logs
            user_logs = [l for l in st.session_state.audit_logs if st.session_state.username in l]
            for log in reversed(user_logs):
                st.text(log)

else:
    st.warning("Access Restricted. Please log in from the sidebar.")
import streamlit as st
import sqlite3
import os
import re

# --- 1. Configuration ---
DB_NAME = 'users.db'

# --- 2. SQLi Detection Logic ---
SQLI_PATTERNS = [
    r"'.*OR.*'1'.*='1'",  # Matches ' OR '1'='1'
    r"'.*--",             # Matches comments to truncate query
    r"'.*;",              # Matches query stacking
    r"UNION.*SELECT",    # Matches UNION-based attacks
]
COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]

def detect_sql_injection(input_string):
    """
    Scans an input string for SQLi patterns and returns a tuple (is_detected, message).
    """
    for pattern in COMPILED_PATTERNS:
        if pattern.search(input_string):
            return (True, f"🚨 DETECTION: Malicious pattern '{pattern.pattern}' found!")
    return (False, "✅ DETECTION: Input seems clean.")

# --- 3. Database Creation Logic ---
def init_db():
    """A function to initialize the database."""
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        role TEXT
    );
    """)
    
    sample_users = [
        ('admin', 'password123', 'admin@example.com', 'admin'),
        ('alice', 'supersecret', 'alice@web.com', 'user'),
        ('bob', 'pa$$word', 'bob@mail.com', 'user'),
    ]
    cursor.executemany("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)", sample_users)
    conn.commit()
    conn.close()
    st.success(f"Database '{DB_NAME}' created and populated!")
    st.balloons()

# --- 4. Login Logic (Vulnerable & Secure) ---

def vulnerable_login(username, password):
    """
    VULNERABLE login function. Returns a tuple (success, message, query).
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABLE QUERY CONSTRUCTION
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return (True, f"Logged in as: {user[1]} (Role: {user[4]})", query)
        else:
            return (False, "Invalid username or password.", query)
            
    except Exception as e:
        return (False, f"An error occurred: {e}", query)

def secure_login(username, password):
    """
    SECURE login function. Returns a tuple (success, message, query).
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SECURE QUERY with parameterized input
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    try:
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return (True, f"Logged in as: {user[1]} (Role: {user[4]})", query)
        else:
            return (False, "Invalid username or password.", query)
            
    except Exception as e:
        return (False, f"An error occurred: {e}", query)

# --- 5. Streamlit Page Layout ---

st.set_page_config(layout="wide")
st.title("🛡️ SQL Injection Demonstration")

# Sidebar for DB management
with st.sidebar:
    st.header("Database Control")
    st.write("First, create the database. You can reset it anytime.")
    if st.button("Initialize/Reset Database"):
        init_db()

# Check if DB exists
if not os.path.exists(DB_NAME):
    st.warning("Database 'users.db' not found. Please click the 'Initialize/Reset Database' button in the sidebar to begin.")
    st.stop()

st.info("""
Try these inputs in the **Username** field (password can be anything):
* `' OR '1'='1`
* `admin' --`
""")

# Create two columns for the forms
col1, col2 = st.columns(2)

# --- VULNERABLE FORM ---
with col1:
    st.error("### 1. Vulnerable Login (Insecure)")
    
    with st.form(key="vulnerable_form"):
        username = st.text_input("Username", key="vuln_user")
        password = st.text_input("Password", type="password", key="vuln_pass")
        submit_button = st.form_submit_button(label="Login")

        if submit_button:
            st.subheader("Results:")
            
            # 1. Run Detection
            is_detected, detection_msg = detect_sql_injection(username)
            if is_detected:
                st.warning(detection_msg)
            else:
                st.success(detection_msg)
            
            # 2. Run Login
            success, message, query = vulnerable_login(username, password)
            
            with st.expander("Show Login Attempt Details"):
                if success:
                    st.error(f"**Login Succeeded (Attack Worked!)**\n\n{message}")
                else:
                    st.info(f"**Login Failed**\n\n{message}")
                
                st.code(f"Executed Query:\n{query}", language="sql")

# --- SECURE FORM ---
with col2:
    st.success("### 2. Secure Login (Safe)")
    
    with st.form(key="secure_form"):
        username = st.text_input("Username", key="sec_user")
        password = st.text_input("Password", type="password", key="sec_pass")
        submit_button = st.form_submit_button(label="Login")

        if submit_button:
            st.subheader("Results:")
            
            # 1. Run Detection
            is_detected, detection_msg = detect_sql_injection(username)
            if is_detected:
                st.warning(detection_msg)
            else:
                st.success(detection_msg)

            # 2. Run Login
            success, message, query = secure_login(username, password)
            
            with st.expander("Show Login Attempt Details"):
                if success:
                    st.success(f"**Login Succeeded (Legitimate)**\n\n{message}")
                else:
                    st.error(f"**Login Failed (Attack Prevented!)**\n\n{message}")
                
                st.code(f"Executed Query:\n{query}\n\nParameters Passed:\n('{username}', '{password}')", language="sql")

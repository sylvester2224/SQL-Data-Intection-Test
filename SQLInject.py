import streamlit as st
import sqlite3
import os
import re
import pandas as pd

# --- 1. Configuration ---
DB_NAME = 'demo_users.db'

# --- 2. SQLi Detection Logic ---
SQLI_PATTERNS = [
    r"'.*OR.*'1'.*='1'",  # Tautology (always true)
    r"'.*--",             # Commenting out the rest of the query
    r"'.*;",              # Query stacking
    r"UNION.*SELECT",    # UNION-based attacks
    r"DROP\s+TABLE",     # Destructive command
]
COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]

def detect_sql_injection(input_string):
    """
    Scans an input string for SQLi patterns and returns a tuple (is_detected, message).
    """
    for pattern in COMPILED_PATTERNS:
        if pattern.search(input_string):
            return (True, f"🚨 DETECTION: Malicious-looking pattern '{pattern.pattern}' found!")
    return (False, "✅ DETECTION: Input seems clean.")

# --- 3. Database Management ---
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
        ('secret_user', 'hidden_pass', 'secret@internal.com', 'user'),
    ]
    cursor.executemany("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)", sample_users)
    conn.commit()
    conn.close()
    st.success(f"Database '{DB_NAME}' created and populated!")
    st.balloons()

def get_db_data():
    """Fetches all data from the users table."""
    if not os.path.exists(DB_NAME):
        return pd.DataFrame(columns=["Error"])
        
    conn = sqlite3.connect(DB_NAME)
    try:
        # Use pandas to easily read the SQL query into a DataFrame
        df = pd.read_sql_query("SELECT * FROM users", conn)
        return df
    except Exception as e:
        # This will happen if the table was DROPPED
        st.error(f"Database error: {e}. The table might have been dropped!")
        return pd.DataFrame(columns=["id", "username", "password", "email", "role"])
    finally:
        conn.close()

# --- 4. Login Logic (Vulnerable & Secure) ---

def vulnerable_login(username, password):
    """
    VULNERABLE login function.
    """
    conn = sqlite3.connect(DB_NAME)
    # This is important to allow pandas to read the results of a UNION query
    conn.row_factory = sqlite3.Row 
    cursor = conn.cursor()
    
    # VULNERABLE QUERY CONSTRUCTION
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        cursor.execute(query)
        # Use fetchall() to get all results (important for UNION attacks)
        results = cursor.fetchall()
        conn.close()
        
        if results:
            # Convert list of Row objects to list of dictionaries
            user_data = [dict(row) for row in results]
            return (True, "Login Succeeded!", query, user_data)
        else:
            return (False, "Invalid username or password.", query, None)
            
    except Exception as e:
        return (False, f"An error occurred: {e}", query, None)

def secure_login(username, password):
    """
    SECURE login function.
    """
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # SECURE QUERY with parameterized input
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    try:
        cursor.execute(query, (username, password))
        results = cursor.fetchall()
        conn.close()
        
        if results:
            user_data = [dict(row) for row in results]
            return (True, f"Login Succeeded!", query, user_data)
        else:
            return (False, "Invalid username or password.", query, None)
            
    except Exception as e:
        return (False, f"An error occurred: {e}", query, None)

# --- 5. Streamlit Page Layout ---

st.set_page_config(layout="wide")
st.title("🛡️ The Interactive SQL Injection Demo")

# Sidebar for DB management
with st.sidebar:
    st.header("Database Control")
    if st.button("Initialize/Reset Database"):
        init_db()
    
    st.header("Current Database State")
    st.write("See what's inside the `users` table.")
    if st.button("Show/Refresh Database"):
        st.dataframe(get_db_data())

# Check if DB exists
if not os.path.exists(DB_NAME):
    st.warning("Database 'users.db' not found. Please click the 'Initialize/Reset Database' button in the sidebar to begin.")
    st.stop()

# --- Explanations ---
with st.expander("What is SQL Injection?"):
    st.markdown("""
    SQL Injection (SQLi) is a vulnerability where an attacker inserts malicious SQL (Structured Query Language) code into a query.
    
    This app's **vulnerable** form builds its SQL query by simply gluing strings together (using an f-string):
    ```python
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    ```
    If an attacker enters `' OR '1'='1` as the username, the final query becomes:
    ```sql
    SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '...'
    ```
    Since `'1'='1'` is **always true**, the `WHERE` clause becomes true for every row, and the database returns all users, logging the attacker in as the first user (usually admin).
    """)

with st.expander("How to Prevent It (The Right Way)"):
    st.markdown("""
    The **secure** form on the right uses **Parameterized Queries** (also called Prepared Statements).
    
    ```python
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    ```
    
    This approach separates the **SQL command** from the **user data**.
    1.  The `query` is sent to the database first, with `?` as placeholders. The database *compiles* this query plan.
    2.  The `username` and `password` variables are sent separately.
    
    The database engine then safely inserts the user data into the placeholders, treating it **only as text**, not as executable code. If an attacker enters `' OR '1'='1`, the database will literally search for a username called `' OR '1'='1`, find none, and the login will (correctly) fail.
    """)

with st.expander("Payloads to Try (Copy and Paste into Username field)"):
    st.code("' OR '1'='1", language="sql")
    st.markdown("Bypasses login by making the `WHERE` clause always true.")
    
    st.code("admin' --", language="sql")
    st.markdown("Logs in as `admin`. The `--` is a SQL comment, which makes the database ignore the rest of the query (the password check).")
    
    st.code("' UNION SELECT 1, username, password, 'N/A', 'N/A' FROM users --", language="sql")
    st.markdown("A `UNION` attack. It bypasses the login and *appends* the results of a second query. This one tries to steal all usernames and passwords from the `users` table. (Note: The `1` and `'N/A'` are placeholders to match the 5 columns of the original table: `id`, `username`, `password`, `email`, `role`.)")
    
    st.code("'; DROP TABLE users --", language="sql")
    st.markdown("**DANGEROUS!** This is a 'query stacking' attack. The `;` ends the first query, and a second, destructive query is added. This will delete the entire `users` table. (Click 'Show/Refresh Database' in the sidebar after trying this to see the effect.)")


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
            st.subheader("Vulnerable Results:")
            
            # 1. Run Detection
            is_detected, detection_msg = detect_sql_injection(username)
            if is_detected:
                st.warning(detection_msg)
            else:
                st.success(detection_msg)
            
            # 2. Run Login
            success, message, query, data = vulnerable_login(username, password)
            
            if success:
                st.error(f"**Status: {message}**")
            else:
                st.info(f"**Status: {message}**")
            
            st.code(f"Executed Query:\n{query}", language="sql")
            
            if data:
                st.write("Data Returned:")
                st.dataframe(pd.DataFrame(data))

# --- SECURE FORM ---
with col2:
    st.success("### 2. Secure Login (Safe)")
    
    with st.form(key="secure_form"):
        username = st.text_input("Username", key="sec_user")
        password = st.text_input("Password", type="password", key="sec_pass")
        submit_button = st.form_submit_button(label="Login")

        if submit_button:
            st.subheader("Secure Results:")
            
            # 1. Run Detection
            is_detected, detection_msg = detect_sql_injection(username)
            if is_detected:
                st.warning(detection_msg)
            else:
                st.success(detection_msg)

            # 2. Run Login
            success, message, query, data = secure_login(username, password)
            
            if success:
                st.success(f"**Status: {message}**")
            else:
                st.error(f"**Status: {message} (Attack Prevented!)**")

            st.code(f"Executed Query:\n{query}\n\nParameters Passed:\n('{username}', '{password}')", language="sql")

            if data:
                st.write("Data Returned:")
                st.dataframe(pd.DataFrame(data))

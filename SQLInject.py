import sqlite3
import os
import re

# --- 1. Configuration ---
DB_NAME = 'demo_users.db'

# --- 2. Database Creation Logic ---
def init_db():
    """Initializes a clean database."""
    print("--- 1. Initializing Database ---")
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
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
        print(f"✅ Database '{DB_NAME}' created and populated successfully.\n")
        
    except Exception as e:
        print(f"❌ Database init error: {e}")
    finally:
        conn.close()

# --- 3. SQLi Detection Logic ---
def detect_sql_injection(input_string):
    """
    Scans an input string for SQLi patterns.
    """
    print(f"    Scanning input: '{input_string}'")
    
    SQLI_PATTERNS = [
        r"'.*OR.*'1'.*='1'",  # Tautology
        r"'.*--",             # Commenting
        r"'.*;",              # Query stacking
        r"UNION.*SELECT",    # UNION attack
        r"DROP\s+TABLE",     # Destructive
    ]
    
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, input_string, re.IGNORECASE):
            print(f"    🚨 DETECTION: Malicious-looking pattern '{pattern}' found!\n")
            return True
            
    print("    ✅ DETECTION: Input seems clean.\n")
    return False

# --- 4. Vulnerable Login Function ---
def vulnerable_login(username, password):
    """
    VULNERABLE login function using f-strings.
    """
    print("  [Vulnerable Login Function]")
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABLE QUERY CONSTRUCTION
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"    Executing query: {query}")
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            print(f"    ❌ VULNERABLE_RESULT: SUCCESS! Logged in as: {user[1]} (Role: {user[4]})\n")
        else:
            print("    ✅ VULNERABLE_RESULT: FAILURE. Invalid credentials.\n")
            
    except Exception as e:
        print(f"    ⚠️ VULNERABLE_RESULT: ERROR. Query failed: {e}\n")
    finally:
        conn.close()

# --- 5. Secure Login Function ---
def secure_login(username, password):
    """
    SECURE login function using parameterized queries.
    """
    print("  [Secure Login Function]")
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SECURE QUERY with parameterized input
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    print(f"    Executing query: {query}")
    print(f"    With parameters: ('{username}', '{password}')")
    
    try:
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        
        if user:
            print(f"    ✅ SECURE_RESULT: SUCCESS. Logged in as: {user[1]} (Role: {user[4]})\n")
        else:
            print(f"    ✅ SECURE_RESULT: FAILURE. Invalid credentials. (Attack prevented!)\n")
            
    except Exception as e:
        print(f"    ⚠️ SECURE_RESULT: ERROR. Query failed: {e}\n")
    finally:
        conn.close()

# --- 6. Main execution block to run the demo ---
if __name__ == "__main__":
    
    # Initialize the database
    init_db()
    
    # Define our list of payloads to test
    attack_payloads = {
        "Login Bypass ('OR '1'='1')": "' OR '1'='1",
        "Comment-based Bypass ('--')": "admin' --",
        "Destructive Query ('; DROP')": "'; DROP TABLE users --"
    }
    
    # --- Run the demo for each attack ---
    for description, payload in attack_payloads.items():
        print("===================================================================")
        print(f"--- 2. Running Test: {description} ---")
        print("===================================================================\n")
        
        # Step A: Run the detection scanner
        print("--- Step A: Run Detection Scanner ---")
        detect_sql_injection(payload)
        
        # Step B: Attempt attack on VULNERABLE function
        print("--- Step B: Attack Vulnerable Function ---")
        vulnerable_login(payload, "password_doesnt_matter")
        
        # Step C: Attempt attack on SECURE function
        print("--- Step C: Attack Secure Function ---")
        secure_login(payload, "password_doesnt_matter")

    print("===================================================================")
    print("--- 3. Verifying Database State ---")
    print("===================================================================\n")
    
    # Check if the 'DROP TABLE' attack worked
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        print(f"✅ Database check: 'users' table is INTACT. Found {len(users)} users.")
        print("The secure function prevented the 'DROP TABLE' attack from running.")
    except Exception as e:
        print(f"❌ Database check: 'users' table is GONE! Error: {e}")
        print("This means the 'DROP TABLE' attack on the VULNERABLE function succeeded.")
    finally:
        conn.close()

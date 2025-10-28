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

# --- 4. Vulnerable Login Function (CORRECTED) ---
def vulnerable_login(username, password):
    """
    VULNERABLE login function using f-strings and executescript.
    """
    print("  [Vulnerable Login Function]")
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABLE QUERY CONSTRUCTION
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"    Executing query: {query}")
    
    try:
        # **THE VULNERABILITY**: Using executescript()
        # This allows multiple statements, including the 'DROP TABLE' one.
        cursor.executescript(query)
        conn.commit()
        
        # NOTE: We can't reliably fetch a user after executescript,
        # but the query *running without error* is the security failure.
        print(f"    ❌ VULNERABLE_RESULT: SUCCESS! The malicious script executed.\n")
            
    except Exception as e:
        # The 'OR 1=1' query will actually fail here because executescript
        # doesn't like an incomplete SELECT. But the DROP TABLE will work.
        print(f"    ⚠️ VULNERABLE_RESULT: Query failed or executed. Error: {e}\n")
    finally:
        conn.close()

# --- 5. Secure Login Function (UNCHANGED) ---
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
        # **THE FIX**: Using execute() with parameters.
        # This *prevents* query stacking.
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
    
    # Define our list of payloads to test
    attack_payloads = {
        "Login Bypass ('OR '1'='1')": "' OR '1'='1",
        "Comment-based Bypass ('--')": "admin' --",
        "Destructive Query ('; DROP')": "'; DROP TABLE users --"
    }
    
    # Run the demo for each attack
    for description, payload in attack_payloads.items():
        # Re-initialize the database for *every* test to make it clean
        init_db()
        
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
        
        # Step D: Verify if the database was destroyed
        print("--- Step D: Verifying Database State ---")
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users")
            users = cursor.fetchall()
            print(f"    ✅ Database check: 'users' table is INTACT. Found {len(users)} users.\n")
        except Exception as e:
            print(f"    ❌ Database check: 'users' table is GONE! Error: {e}\n")
        finally:
            conn.close()

    print("===================================================================")
    print("--- Demo Complete ---")
    print("===================================================================")
    # Clean up the created database file
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)
    print(f"Cleaned up {DB_NAME}.")

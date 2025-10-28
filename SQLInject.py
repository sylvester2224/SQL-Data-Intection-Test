import streamlit as st
import sqlite3
import os
import re
import pandas as pd
import time

# --- Database Setup ---
DB_NAME = "project_db.sqlite"

def create_database():
    """
    Creates/resets the database and populates it with sample data.
    Uses st.write to show output in the app.
    """
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)
        st.sidebar.write(f"Removed old database '{DB_NAME}'.")

    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        st.sidebar.success(f"Created new database '{DB_NAME}'.")

        # 1. Create the 'users' table
        create_table_sql = """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        );
        """
        c.execute(create_table_sql)
        st.sidebar.write("Created 'users' table.")

        # 2. Insert 20 rows of sample data
        sample_users = [
            ('admin', 'password123', 'admin@example.com', 'admin'),
            ('alice', 'alice_pass', 'alice@web.com', 'user'),
            ('bob', 'bob_secret', 'bob@mail.com', 'user'),
            ('charlie', 'charlie!@#', 'charlie@web.com', 'user'),
            ('dave', 'daves_pass', 'dave@mail.com', 'user'),
            ('eve', 'eve_hacker', 'eve@danger.com', 'guest'),
            ('frank', 'frank_123', 'frank@web.com', 'user'),
            ('grace', 'grace_pass', 'grace@mail.com', 'user'),
            ('heidi', 'heidi_sec', 'heidi@web.com', 'user'),
            ('ivan', 'ivan_ivan', 'ivan@mail.com', 'user'),
            ('judy', 'judy_pass', 'judy@web.com', 'user'),
            ('mallory', 'mallory_evil', 'mallory@danger.com', 'guest'),
            ('oscar', 'oscar_oscar', 'oscar@mail.com', 'user'),
            ('peggy', 'peggy_1', 'peggy@web.com', 'user'),
            ('trent', 'trent_sec', 'trent@mail.com', 'user'),
            ('victor', 'victor_v', 'victor@web.com', 'user'),
            ('wendy', 'wendy_pass', 'wendy@mail.com', 'user'),
            ('xander', 'xander_x', 'xander@web.com', 'user'),
            ('yara', 'yara_yara', 'yara@mail.com', 'user'),
            ('zack', 'zack_z', 'zack@web.com', 'user')
        ]
        
        c.executemany("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)", sample_users)
        st.sidebar.write(f"Inserted {len(sample_users)} rows.")

        conn.commit()
        conn.close()
        st.sidebar.write("Database is ready.")
        st.balloons()
        return True
    except Exception as e:
        st.sidebar.error(f"An error occurred: {e}")
        return False

@st.cache_data(ttl=1) # Cache the data for 1 second to show live updates
def get_database_contents():
    """
    Fetches all user data from the database to display in a table.
    """
    if not os.path.exists(DB_NAME):
        return pd.DataFrame(columns=["id", "username", "password", "email", "role"]), "Database file not found. Please create it."
        
    conn = sqlite3.connect(DB_NAME)
    try:
        # Use pandas to read SQL query directly into a DataFrame
        df = pd.read_sql_query("SELECT id, username, password, email, role FROM users", conn)
        return df, None
    except pd.errors.DatabaseError as e:
        if "no such table: users" in str(e):
            return pd.DataFrame(columns=["id", "username", "password", "email", "role"]), "Error: The 'users' table has been dropped!"
        else:
            return pd.DataFrame(columns=["id", "username", "password", "email", "role"]), f"Could not read database: {e}"
    except Exception as e:
        return pd.DataFrame(columns=["id", "username", "password", "email", "role"]), f"An unknown error occurred: {e}"
    finally:
        conn.close()

# --- Vulnerable Function ---
def unsafe_login(username_input, password_input):
    """
    Demonstrates a VULNERABLE login function.
    Returns a dictionary with query, status, and data.
    """
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # THE VULNERABILITY: Using f-string to build a query
    query = f"SELECT * FROM users WHERE username = '{username_input}' AND password = '{password_input}';"
    
    results_data = []
    status = ""
    try:
        # Use executescript to allow stacked queries (the injection)
        c.executescript(query)
        # c.executescript will execute all commands, but fetchall() will only
        # return results from the *last* valid SELECT statement.
        # If the last command was DROP or UPDATE, fetchall() might be empty.
        results = c.fetchall()
        
        if results:
            status = "Login SUCCESSFUL!"
            for row in results:
                results_data.append(row)
        else:
            # This 'else' block will also be hit if the injected command
            # was UPDATE or DROP, as they don't return data like SELECT.
            status = "Login FAILED or no data returned."
            
    except sqlite3.Error as e:
        status = f"A database error occurred: {e}"
    
    # We must commit to save changes from UPDATE or DROP
    conn.commit()
    conn.close()
    
    # Special check for our known attacks
    if "UPDATE" in username_input.upper():
        status = "ATTACK SUCCESSFUL: The `UPDATE` command was injected and executed."
    elif "DROP" in username_input.upper():
        status = "ATTACK SUCCESSFUL: The `DROP TABLE` command was injected and executed."
    elif "'1'='1'" in username_input:
        status = "ATTACK SUCCESSFUL: Login bypassed and all user data was returned."

    return {"query": query, "status": status, "data": results_data}

# --- Secure Function ---
def safe_login(username_input, password_input):
    """
    Demonstrates a SECURE login function using Parameterized Queries.
    Returns a dictionary with query, status, and data.
    """
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # THE PREVENTION: Using '?' as placeholders
    query = "SELECT * FROM users WHERE username = ? AND password = ?;"
    
    results_data = []
    status = ""
    try:
        # Pass the inputs as a separate tuple
        # .execute() CANNOT run multiple commands, so UPDATE/DROP injections fail.
        c.execute(query, (username_input, password_input))
        results = c.fetchall()
        
        if results:
            status = "Login SUCCESSFUL!"
            for row in results:
                results_data.append(row)
        else:
            status = "Login FAILED: User not found or password incorrect."
            
    except sqlite3.Error as e:
        status = f"A database error occurred: {e}"

    # No commit is needed since we only (safely) tried to SELECT
    conn.close()
    
    if "UPDATE" in username_input.upper() or "DROP" in username_input.upper():
        status = "ATTACK PREVENTED: The database correctly searched for a literal username containing 'UPDATE'/'DROP' and found no match. No data was changed."

    return {
        "query": f"Query Template: {query}\nParameters: ('{username_input}', '{password_input}')",
        "status": status,
        "data": results_data
    }

# --- Detection Function ---
def simple_input_scanner(input_string):
    """
    A very basic "scanner" that flags suspicious characters.
    """
    suspicious_pattern = r"('|--|;| OR | AND |UPDATE|DROP)"
    
    if re.search(suspicious_pattern, input_string, re.IGNORECASE):
        return f":warning: **[DETECTED]** Input contains suspicious characters: `'{input_string}'`"
    else:
        return f":white_check_mark: **[CLEAN]** Input seems clean: `'{input.string}'`"

# --- Main Streamlit App ---
def main():
    st.set_page_config(page_title="SQL Injection Demo", layout="wide")
    st.title("SQL Injection: The Good, The Bad, & The Secure 🛡️")

    # --- Sidebar for Database Controls ---
    st.sidebar.title("Database Controls 🎛️")
    st.sidebar.info("Use this button to create a new database or reset the demo if you've broken it.")
    if st.sidebar.button("Create / Reset Database"):
        create_database()
        st.experimental_rerun() # Rerun the script to update the UI

    if not os.path.exists(DB_NAME):
        st.warning("Please create the database using the button in the sidebar to start the demo.")
        st.stop()

    # --- Main Page Content ---
    st.header("🤔 What is SQL Injection?")
    st.markdown("""
    SQL Injection (SQLi) is a type of cyberattack where an attacker inserts malicious SQL (Structured Query Language) code into a query.
    
    **Why is this bad?** If the application is built insecurely, it might *execute* the attacker's code.
    This can allow an attacker to:
    - **View** data they aren't supposed to see (like all users' passwords).
    - **Change** data (like making themselves an 'admin').
    - **Destroy** data (like deleting the entire user table).
    
    This demo will show you exactly how this works and how to prevent it.
    """)

    st.header("1. The Database 🗃️")
    with st.expander("Click to see the Current Database Contents"):
        db_contents, error_msg = get_database_contents()
        if error_msg:
            st.error(f"**{error_msg}**\nPlease click the 'Create / Reset Database' button in the sidebar.")
        st.dataframe(db_contents, use_container_width=True)

    st.markdown("---")
    st.header("2. The Demonstration: Unsafe vs. Safe")
    
    tab1, tab2 = st.tabs(["🔴 The Vulnerability (UNSAFE)", "🟢 The Prevention (SAFE)"])

    # --- UNSAFE TAB ---
    with tab1:
        st.warning("This login form is **DANGEROUS**. It builds the SQL query by directly pasting the user's input into a string (using an f-string).")
        
        attack_payloads = {
            "Attack 1: Bypass Login": {
                "payload": "' OR '1'='1' --",
                "desc": "This payload tricks the query to become `WHERE username = '' OR '1'='1'`. Since `'1'='1'` is always true, the `WHERE` clause is true for *every single row*, and the database returns all users."
            },
            "Attack 2: Change Data": {
                "payload": "eve'; UPDATE users SET role='admin' WHERE username='eve' --",
                "desc": "This uses a semicolon (`;`) to *stack* a new command. It closes the first command and then runs a totally new `UPDATE` command, changing 'eve' from a 'guest' to an 'admin'."
            },
            "Attack 3: Destroy Data": {
                "payload": "'; DROP TABLE users; --",
                "desc": "This is the most destructive attack. It stacks a `DROP TABLE` command, which completely deletes the `users` table from the database. **Try this to see the app break!**"
            }
        }
        
        attack_choice = st.selectbox("Choose an attack to demonstrate:", attack_payloads.keys())
        st.markdown(f"**What this attack does:** {attack_payloads[attack_choice]['desc']}")
        st.write("Copy this payload into the **Username** field (password can be anything):")
        st.code(attack_payloads[attack_choice]['payload'], language="sql")
        
        with st.form("unsafe_form"):
            unsafe_user = st.text_input("Username", key="unsafe_user")
            unsafe_pass = st.text_input("Password", type="password", key="unsafe_pass")
            unsafe_submitted = st.form_submit_button("Attempt Unsafe Login")

        if unsafe_submitted:
            st.subheader("Unsafe Login Result:")
            result = unsafe_login(unsafe_user, unsafe_pass)
            
            st.write(f"**Status:**")
            if "ATTACK SUCCESSFUL" in result['status']:
                st.error(result['status'])
                if "DROP" in result['status']:
                    st.warning("The table is gone! Refresh this page (or click the expander above) to see the error. Click 'Create / Reset Database' to fix it.")
            else:
                st.info(result['status'])
                
            st.write("**Full Query Executed:**")
            st.code(result['query'], language="sql")
            
            if result['data']:
                st.write("**Data Returned:**")
                df = pd.DataFrame(result['data'], columns=["id", "username", "password", "email", "role"])
                st.dataframe(df, use_container_width=True)

    # --- SAFE TAB ---
    with tab2:
        st.success("This login form is **SAFE**. It uses **Parameterized Queries** (also called Prepared Statements).")
        st.markdown("""
        This method **separates the command from the data**.
        - **The Command:** `SELECT * FROM users WHERE username = ? AND password = ?;`
        - **The Data:** `('eve'; UPDATE ...)`
        
        The database *knows* the `?` placeholders are for data *only*. It will literally search for a user whose name is the entire string `'eve'; UPDATE ...`. It **will not** execute the `UPDATE` command.
        """)
        
        st.subheader("Try the Attacks Again!")
        st.info("Copy any of the attack strings from the 'Unsafe' tab and paste them here. Watch how they all fail harmlessly.")

        with st.form("safe_form"):
            safe_user = st.text_input("Username", key="safe_user")
            safe_pass = st.text_input("Password", type="password", key="safe_pass")
            safe_submitted = st.form_submit_button("Attempt Safe Login")

        if safe_submitted:
            st.subheader("Safe Login Result:")
            result = safe_login(safe_user, safe_pass)
            
            st.write(f"**Status:**")
            if "ATTACK PREVENTED" in result['status']:
                st.success(result['status'])
            else:
                st.info(result['status'])
            
            st.write("**Query Logic Executed:**")
            st.code(result['query'], language="sql")
            
            if result['data']:
                st.write("**Data Returned:**")
                df = pd.DataFrame(result['data'], columns=["id", "username", "password", "email", "role"])
                st.dataframe(df, use_container_width=True)
            else:
                st.write("No data was returned, as expected.")
    
    st.markdown("---")

    # --- Part 3: Detection ---
    st.header("4. Bonus: Simple Input 'Detection' 🔍")
    st.info("""
    Prevention (like in the 'Safe' tab) is **always** the best security.
    
    Detection is a weaker, secondary layer. This simple scanner just looks for suspicious-looking text. 
    An attacker could easily bypass this by using different text encodings or more complex queries, but it can stop basic attacks.
    """)
    
    scan_input = st.text_input("Enter some text to scan:")
    if scan_input:
        scan_result = simple_input_scanner(scan_input)
        st.markdown(scan_result)

if __name__ == "__main__":
    main()

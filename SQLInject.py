import streamlit as st
import sqlite3
import os
import re
import pandas as pd  # Streamlit works great with Pandas DataFrames

# --- Database Setup ---
DB_NAME = "project_db.sqlite"

def create_database():
    """
    Creates/resets the database and populates it with sample data.
    Uses st.write to show output in the app.
    """
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)
        st.write(f"Removed old database '{DB_NAME}'.")

    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        st.success(f"Created and connected to new database '{DB_NAME}'.")

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
        st.write("Created 'users' table.")

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
        st.write(f"Inserted {len(sample_users)} rows of data.")

        conn.commit()
        conn.close()
        st.write("Changes saved and connection closed.")
        st.balloons()
        return True
    except Exception as e:
        st.error(f"An error occurred: {e}")
        return False

def get_database_contents():
    """
    Fetches all user data from the database to display in a table.
    """
    if not os.path.exists(DB_NAME):
        return pd.DataFrame(columns=["id", "username", "password", "email", "role"])
        
    conn = sqlite3.connect(DB_NAME)
    try:
        # Use pandas to read SQL query directly into a DataFrame
        df = pd.read_sql_query("SELECT id, username, password, email, role FROM users", conn)
        return df
    except Exception as e:
        st.error(f"Could not read database: {e}")
        return pd.DataFrame(columns=["id", "username", "password", "email", "role"])
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
    try:
        # Use executescript to allow stacked queries (the injection)
        c.executescript(query)
        results = c.fetchall()
        
        if results:
            status = "Login SUCCESSFUL!"
            for row in results:
                results_data.append(row)
        else:
            status = "Login FAILED: User not found or password incorrect."
            
    except sqlite3.Error as e:
        status = f"An error occurred: {e}"

    conn.close()
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
        c.execute(query, (username_input, password_input))
        results = c.fetchall()
        
        if results:
            status = "Login SUCCESSFUL!"
            for row in results:
                results_data.append(row)
        else:
            status = "Login FAILED: User not found or password incorrect."
            
    except sqlite3.Error as e:
        status = f"An error occurred: {e}"

    conn.close()
    
    # For demonstration, we show the template and the data passed
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
    suspicious_pattern = r"('|--|;| OR | AND )"
    
    if re.search(suspicious_pattern, input_string, re.IGNORECASE):
        return f"[DETECTED] Input contains suspicious characters: `'{input_string}'`"
    else:
        return f"[CLEAN] Input seems clean: `'{input_string}'`"

# --- Main Streamlit App ---
def main():
    st.set_page_config(page_title="SQL Injection Demo", layout="wide")
    st.title("SQL Injection: Demonstration & Prevention")
    st.write(
        "This app demonstrates how a SQL Injection (SQLi) attack works and, "
        "more importantly, how to easily prevent it. This is for educational purposes only."
    )

    # --- Part 1: Database Setup ---
    st.header("1. The Database")
    st.write("First, we need a simple database. This button will create a file named `project_db.sqlite` with 20 sample users.")
    
    if st.button("Create / Reset Database"):
        create_database()

    if not os.path.exists(DB_NAME):
        st.warning("Please create the database to proceed with the demo.")
        st.stop()  # Don't run the rest of the app until DB is created

    # Show database contents
    st.subheader("Current Database Contents")
    st.dataframe(get_database_contents(), use_container_width=True)
    st.markdown("---")

    # --- Part 2: The Attack & Prevention ---
    col1, col2 = st.columns(2)

    with col1:
        st.header("2. The Vulnerability (UNSAFE)")
        st.warning("This login form is **DANGEROUS**. It builds the SQL query by directly adding the user's input into a string.")
        
        with st.form("unsafe_form"):
            st.write("Try a normal login (e.g., `alice` / `alice_pass`)")
            unsafe_user = st.text_input("Username", key="unsafe_user")
            unsafe_pass = st.text_input("Password", type="password", key="unsafe_pass")
            
            st.subheader("Attack 1: Bypassing Login")
            st.write("Enter this into the **Username** field and *any* password to log in as *all users*.")
            st.code("' OR '1'='1' --")

            st.subheader("Attack 2: Changing Data")
            st.write("This attack uses a semicolon (`;`) to *stack* a new command. It tricks the database into running an `UPDATE` command to make a 'guest' user an 'admin'.")
            st.write("Enter this into the **Username** field (password can be anything):")
            st.code("eve'; UPDATE users SET role='admin' WHERE username='eve' --")
            
            unsafe_submitted = st.form_submit_button("Attempt Unsafe Login")

        if unsafe_submitted:
            st.subheader("Unsafe Login Result:")
            result = unsafe_login(unsafe_user, unsafe_pass)
            st.write(f"**Status:** {result['status']}")
            st.write("**Full Query Executed:**")
            st.code(result['query'], language="sql")
            
            if result['data']:
                st.write("**Data Returned (from the `SELECT` part):**")
                # Format data nicely
                df = pd.DataFrame(result['data'], columns=["id", "username", "password", "email", "role"])
                st.dataframe(df, use_container_width=True)
            
            # Check if the destructive attack was performed
            if "UPDATE" in unsafe_user.upper():
                st.error("ATTACK SUCCESSFUL! The `UPDATE` command was injected and executed.")
                st.info("Scroll up to the 'Current Database Contents' table. You will see that user 'eve' is now an 'admin'!")
                st.warning("This change is permanent in the database until you click 'Create / Reset Database' again.")

    with col2:
        st.header("3. The Prevention (SAFE)")
        st.success("This login form is **SAFE**. It uses **Parameterized Queries** (the `?` placeholders) to separate the command from the data.")
        
        with st.form("safe_form"):
            st.write("Try a normal login (e.g., `admin` / `password123`)")
            safe_user = st.text_input("Username", key="safe_user")
            safe_pass = st.text_input("Password", type="password", key="safe_pass")
            
            st.subheader("Try the Attacks Again!")
            st.write("Enter the *same attack strings* from the 'Unsafe' side (both the `' OR '1'='1' --` and the `UPDATE` one).")
            st.write("Watch how they both fail safely!")

            safe_submitted = st.form_submit_button("Attempt Safe Login")

        if safe_submitted:
            st.subheader("Safe Login Result:")
            result = safe_login(safe_user, safe_pass)
            st.write(f"**Status:** {result['status']}")
            st.write("**Query Logic Executed:**")
            st.code(result['query'], language="sql")
            
            if result['data']:
                st.write("**Data Returned:**")
                df = pd.DataFrame(result['data'], columns=["id", "username", "password", "email", "role"])
                st.dataframe(df, use_container_width=True)
            else:
                st.write("No data was returned. The database correctly and safely searched for a user with the literal (and non-existent) name you entered.")
                if "UPDATE" in safe_user.upper():
                    st.success("The `UPDATE` attack was **PREVENTED**. The database was not changed.")
    
    st.markdown("---")

    # --- Part 3: Detection ---
    st.header("4. Bonus: Simple Input 'Detection'")
    st.info("Prevention (like in Part 3) is **always** the best security. Detection is a weaker, secondary layer. This simple scanner just looks for suspicious-looking text.")
    
    scan_input = st.text_input("Enter some text to scan:")
    if scan_input:
        scan_result = simple_input_scanner(scan_input)
        if "DETECTED" in scan_result:
            st.warning(scan_result)
        else:
            st.success(scan_result)

if __name__ == "__main__":
    main()


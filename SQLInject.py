import sqlite3
import os
import re
from flask import Flask, request, render_template_string, redirect, url_for

# --- 1. Configuration ---
app = Flask(__name__)
DB_NAME = 'users.db'

# --- 2. SQLi Detection Logic (from detect_attack.py) ---
SQLI_PATTERNS = [
    r"'.*OR.*'1'.*='1'",  # Matches ' OR '1'='1'
    r"'.*--",             # Matches comments to truncate query
    r"'.*;",              # Matches query stacking
    r"UNION.*SELECT",    # Matches UNION-based attacks
]
COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]

def detect_sql_injection(input_string):
    """
    Scans an input string for SQLi patterns and returns a detection message.
    """
    for pattern in COMPILED_PATTERNS:
        if pattern.search(input_string):
            return f"🚨 DETECTION: Malicious pattern '{pattern.pattern}' found in input!"
    return "✅ DETECTION: Input seems clean."

# --- 3. Database Creation Logic (from create_db.py) ---
@app.route('/init_db')
def init_db():
    """A web route to initialize the database."""
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
    
    # Redirect back to the main page
    return redirect(url_for('homepage'))

# --- 4. Login Logic (Vulnerable & Secure) ---

def vulnerable_login(username, password):
    """
    VULNERABLE login function. Returns a result string.
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
            return f"--- VULNERABLE SUCCESS (Attack) ---\nLogged in as: {user[1]} (Role: {user[4]})\nQuery was: {query}"
        else:
            return f"--- VULNERABLE FAILURE ---\nInvalid username or password.\nQuery was: {query}"
            
    except Exception as e:
        return f"--- VULNERABLE ERROR ---\n{e}\nQuery was: {query}"

def secure_login(username, password):
    """
    SECURE login function. Returns a result string.
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
            return f"--- SECURE SUCCESS (Legitimate) ---\nLogged in as: {user[1]} (Role: {user[4]})\nQuery was: {query}"
        else:
            return f"--- SECURE FAILURE ---\nInvalid username or password.\nQuery was: {query}"
            
    except Exception as e:
        return f"--- SECURE ERROR ---\n{e}\nQuery was: {query}"

# --- 5. Web Page (HTML Template) ---
# We define the HTML right in the Python file for simplicity.
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SQLi Demo</title>
    <style>
        body { font-family: sans-serif; margin: 2em; }
        .container { display: flex; gap: 2em; }
        .box { border: 1px solid #ccc; padding: 1em; border-radius: 5px; }
        pre { background-color: #f4f4f4; padding: 1em; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; }
        input[type=text], input[type=password] { width: 100%; box-sizing: border-box; }
        h2 { border-bottom: 2px solid; }
        .danger { color: red; }
        .safe { color: green; }
    </style>
</head>
<body>
    <h1>SQL Injection Demo</h1>
    <p>
        <a href="/init_db">Click here to initialize/reset the database.</a>
        (Users: admin, alice, bob)
    </p>

    <div class="container">
        <div class="box">
            <h2 class="danger">Vulnerable Login (Uses f-strings)</h2>
            <form method="POST">
                <input type="hidden" name="form_type" value="vulnerable">
                <label>Username:</label>
                <input type="text" name="username">
                <label>Password:</label>
                <input type="password" name="password">
                <br><br>
                <button type="submit">Login</button>
            </form>
        </div>

        <div class="box">
            <h2 class="safe">Secure Login (Uses Parameters)</h2>
            <form method="POST">
                <input type="hidden" name="form_type" value="secure">
                <label>Username:</label>
                <input type="text" name="username">
                <label>Password:</label>
                <input type="password" name="password">
                <br><br>
                <button type="submit">Login</button>
            </form>
        </div>
    </div>

    {% if result %}
    <h2>Results</h2>
    <pre>{{ detection_result }}</pre>
    <pre>{{ result }}</pre>
    {% endif %}

    <h3>Try these inputs in the Username field (and any password):</h3>
    <pre>' OR '1'='1'</pre>
    <pre>admin' --</pre>

</body>
</html>
"""

# --- 6. Main Web Route ---
@app.route('/', methods=['GET', 'POST'])
def homepage():
    """
    Main page, handles both showing the forms (GET) 
    and processing the login (POST).
    """
    result = ""
    detection_result = ""
    
    if request.method == 'POST':
        # Get data from the form that was submitted
        username = request.form['username']
        password = request.form['password']
        form_type = request.form['form_type']
        
        # 1. Run the detector on the username input
        detection_result = detect_sql_injection(username)
        
        # 2. Run the correct login function
        if form_type == 'vulnerable':
            result = vulnerable_login(username, password)
        elif form_type == 'secure':
            result = secure_login(username, password)

    # Show the webpage
    return render_template_string(HTML_TEMPLATE, result=result, detection_result=detection_result)

# --- 7. Run the App ---
if __name__ == '__main__':
    if not os.path.exists(DB_NAME):
        print("Database not found. Initializing...")
        init_db()
    
    print("Starting Flask server...")
    print("Open your browser and go to: http://127.0.0.1:5000")
    app.run(debug=True) # debug=True auto-reloads when you save the file

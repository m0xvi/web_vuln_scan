from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    cursor.execute('''INSERT INTO users (username, password) VALUES ('admin', 'password')''')
    cursor.execute('''INSERT INTO users (username, password) VALUES ('user', 'password')''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return """
    <h1>SQL Injection Test Application</h1>
    <ul>
        <li><a href="/login">Login Form (Error-based)</a></li>
        <li><a href="/search">Search Form (Union-based)</a></li>
        <li><a href="/blind">Blind SQL Injection</a></li>
        <li><a href="/timebased">Time-based SQL Injection</a></li>
    </ul>
    """

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        conn = sqlite3.connect('test.db')
        cursor = conn.cursor()
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            if user:
                return f"<h2>Welcome {user[1]}!</h2>"
            else:
                error = "Invalid credentials"
        except sqlite3.Error as e:
            error = str(e)
        conn.close()
    return render_template_string('''
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
        <p>{{ error }}</p>
    ''', error=error)

@app.route('/search', methods=['GET', 'POST'])
def search():
    results = None
    if request.method == 'POST':
        term = request.form['term']
        query = f"SELECT * FROM users WHERE username LIKE '%{term}%'"
        conn = sqlite3.connect('test.db')
        cursor = conn.cursor()
        try:
            cursor.execute(query)
            results = cursor.fetchall()
        except sqlite3.Error as e:
            results = str(e)
        conn.close()
    return render_template_string('''
        <form method="POST">
            Search: <input type="text" name="term"><br>
            <input type="submit" value="Search">
        </form>
        {% if results %}
            <ul>
                {% for result in results %}
                    <li>{{ result }}</li>
                {% endfor %}
            </ul>
        {% endif %}
    ''', results=results)

@app.route('/blind', methods=['GET', 'POST'])
def blind():
    result = None
    if request.method == 'POST':
        user_id = request.form['user_id']
        query = f"SELECT * FROM users WHERE id = {user_id}"
        conn = sqlite3.connect('test.db')
        cursor = conn.cursor()
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            if user:
                result = "User exists"
            else:
                result = "User does not exist"
        except sqlite3.Error as e:
            result = str(e)
        conn.close()
    return render_template_string('''
        <form method="POST">
            User ID: <input type="text" name="user_id"><br>
            <input type="submit" value="Check">
        </form>
        <p>{{ result }}</p>
    ''', result=result)

@app.route('/timebased', methods=['GET', 'POST'])
def timebased():
    result = None
    if request.method == 'POST':
        user_id = request.form['user_id']
        query = f"SELECT CASE WHEN (SELECT COUNT(*) FROM users WHERE id = {user_id} AND 1=1) THEN 1 ELSE pg_sleep(5) END"
        conn = sqlite3.connect('test.db')
        cursor = conn.cursor()
        start_time = time.time()
        try:
            cursor.execute(query)
            result = "Query executed"
        except sqlite3.Error as e:
            result = str(e)
        end_time = time.time()
        conn.close()
        execution_time = end_time - start_time
        return render_template_string('''
            <form method="POST">
                User ID: <input type="text" name="user_id"><br>
                <input type="submit" value="Check">
            </form>
            <p>{{ result }}</p>
            <p>Execution time: {{ execution_time }} seconds</p>
        ''', result=result, execution_time=execution_time)
    return render_template_string('''
        <form method="POST">
            User ID: <input type="text" name="user_id"><br>
            <input type="submit" value="Check">
        </form>
        <p>{{ result }}</p>
    ''', result=result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)

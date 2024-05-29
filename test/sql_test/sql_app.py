from flask import Flask, request, render_template_string
import sqlite3
import time

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

css = '''
<style>
body {
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 0;
    background-color: #f9f9f9;
    color: #333;
}

header {
    background-color: #4CAF50;
    color: white;
    padding: 1em;
    text-align: center;
}

nav ul {
    list-style-type: none;
    margin: 0;
    padding: 0;
    overflow: hidden;
    background-color: #333;
}

nav ul li {
    float: left;
}

nav ul li a {
    display: block;
    color: white;
    text-align: center;
    padding: 14px 16px;
    text-decoration: none;
}

nav ul li a:hover {
    background-color: #111;
}

main {
    padding: 20px;
}

footer {
    background-color: #333;
    color: white;
    text-align: center;
    padding: 1em;
    position: fixed;
    bottom: 0;
    width: 100%;
}

.content {
    max-width: 800px;
    margin: auto;
    background: white;
    padding: 20px;
    box-shadow: 0 0 10px rgba(0,0,0,0.1);
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 20px 0;
}

table, th, td {
    border: 1px solid #ddd;
}

th, td {
    padding: 8px;
    text-align: left;
}

th {
    background-color: #4CAF50;
    color: white;
}

tr:nth-child(even) {
    background-color: #f2f2f2;
}

.button {
    background-color: #4CAF50;
    border: none;
    color: white;
    padding: 10px 20px;
    text-align: center;
    text-decoration: none;
    display: inline-block;
    font-size: 16px;
    margin: 4px 2px;
    cursor: pointer;
}
</style>
'''

@app.route('/')
def index():
    return render_template_string(f'''
    {css}
    <header>
        <h1>SQL Injection Test Application</h1>
    </header>
    <nav>
        <ul>
            <li><a href="/login">Login Form (Error-based)</a></li>
            <li><a href="/search">Search Form (Union-based)</a></li>
            <li><a href="/blind">Blind SQL Injection</a></li>
            <li><a href="/timebased">Time-based SQL Injection</a></li>
        </ul>
    </nav>
    <main>
        <div class="content">
            <h2>Welcome to the SQL Injection Test Application</h2>
            <p>This application is designed to demonstrate various SQL Injection techniques and their effects.</p>
        </div>
    </main>
    <footer>
        <p>&copy; 2024 SQL Injection Test Application</p>
    </footer>
    ''')

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
                return render_template_string(f'''
                {css}
                <header>
                    <h1>SQL Injection Test Application</h1>
                </header>
                <main>
                    <div class="content">
                        <h2>Welcome {user[1]}!</h2>
                    </div>
                </main>
                <footer>
                    <p>&copy; 2024 SQL Injection Test Application</p>
                </footer>
                ''')
            else:
                error = "Invalid credentials"
        except sqlite3.Error as e:
            error = str(e)
        conn.close()
    return render_template_string(f'''
        {css}
        <header>
            <h1>SQL Injection Test Application</h1>
        </header>
        <main>
            <div class="content">
                <form method="POST">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username"><br>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password"><br>
                    <input class="button" type="submit" value="Login">
                </form>
                <p>{{{{ error }}}}</p>
            </div>
        </main>
        <footer>
            <p>&copy; 2024 SQL Injection Test Application</p>
        </footer>
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
    return render_template_string(f'''
        {css}
        <header>
            <h1>SQL Injection Test Application</h1>
        </header>
        <main>
            <div class="content">
                <form method="POST">
                    <label for="term">Search:</label>
                    <input type="text" id="term" name="term"><br>
                    <input class="button" type="submit" value="Search">
                </form>
                {{% if results %}}
                    <ul>
                        {{% for result in results %}}
                            <li>{{{{ result }}}}</li>
                        {{% endfor %}}
                    </ul>
                {{% endif %}}
            </div>
        </main>
        <footer>
            <p>&copy; 2024 SQL Injection Test Application</p>
        </footer>
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
    return render_template_string(f'''
        {css}
        <header>
            <h1>SQL Injection Test Application</h1>
        </header>
        <main>
            <div class="content">
                <form method="POST">
                    <label for="user_id">User ID:</label>
                    <input type="text" id="user_id" name="user_id"><br>
                    <input class="button" type="submit" value="Check">
                </form>
                <p>{{{{ result }}}}</p>
            </div>
        </main>
        <footer>
            <p>&copy; 2024 SQL Injection Test Application</p>
        </footer>
    ''', result=result)

@app.route('/timebased', methods=['GET', 'POST'])
def timebased():
    result = None
    if request.method == 'POST':
        user_id = request.form['user_id']
        start_time = time.time()
        if user_id == '1':
            time.sleep(5)  # Simulate time delay
        conn = sqlite3.connect('test.db')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE id = {user_id}"
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            if user:
                result = "User exists"
            else:
                result = "User does not exist"
        except sqlite3.Error as e:
            result = str(e)
        end_time = time.time()
        conn.close()
        execution_time = end_time - start_time
        return render_template_string(f'''
            {css}
            <header>
                <h1>SQL Injection Test Application</h1>
            </header>
            <main>
                <div class="content">
                    <form method="POST">
                        <label for="user_id">User ID:</label>
                        <input type="text" id="user_id" name="user_id"><br>
                        <input class="button" type="submit" value="Check">
                    </form>
                    <p>{{{{ result }}}}</p>
                    <p>Execution time: {{{{ execution_time }}}} seconds</p>
                </div>
            </main>
            <footer>
                <p>&copy; 2024 SQL Injection Test Application</p>
            </footer>
        ''', result=result, execution_time=execution_time)
    return render_template_string(f'''
        {css}
        <header>
            <h1>SQL Injection Test Application</h1>
        </header>
        <main>
            <div class="content">
                <form method="POST">
                    <label for="user_id">User ID:</label>
                    <input type="text" id="user_id" name="user_id"><br>
                    <input class="button" type="submit" value="Check">
                </form>
                <p>{{{{ result }}}}</p>
            </div>
        </main>
        <footer>
            <p>&copy; 2024 SQL Injection Test Application</p>
        </footer>
    ''', result=result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)

import sqlite3

connection = sqlite3.connect('test.db')

with connection:
    connection.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    connection.execute("INSERT INTO users (username, password) VALUES ('admin', 'password123')")
    connection.execute("INSERT INTO users (username, password) VALUES ('user1', 'password456')")
    connection.execute("INSERT INTO users (username, password) VALUES ('user2', 'password789')")

connection.close()

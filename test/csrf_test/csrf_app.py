from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = 'supersecretkey'

users = {'admin': 'password123'}
accounts = {'admin': 1000}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('transfer'))
        else:
            flash('Invalid credentials, please try again.')
    return render_template('login.html')

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        to_user = request.form['to_user']
        amount = int(request.form['amount'])
        if to_user in accounts:
            accounts[session['username']] -= amount
            accounts[to_user] += amount
            flash('Transfer successful!')
        else:
            flash('User not found.')
    return render_template('transfer.html', balance=accounts[session['username']])

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

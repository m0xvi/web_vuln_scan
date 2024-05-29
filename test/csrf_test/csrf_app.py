from flask import Flask, render_template, request, redirect, url_for, session
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    submit = SubmitField('Login')

class TransferForm(FlaskForm):
    amount = StringField('Amount', validators=[DataRequired()])
    to_account = StringField('To Account', validators=[DataRequired()])
    submit = SubmitField('Submit')

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        session['user'] = form.username.data
        return redirect(url_for('transfer'))
    return render_template('login.html', form=form)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user' not in session:
        return redirect(url_for('login'))
    form = TransferForm()
    if form.validate_on_submit():
        return f"Transfer {form.amount.data} to {form.to_account.data} by {session['user']}"
    return render_template('form.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5002)

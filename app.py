from flask import Flask, render_template, redirect, request, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, EmailField, TelField
from wtforms.validators import DataRequired, ValidationError, Email
from password_strength import PasswordPolicy
from database.db import connectDB
from argon2 import PasswordHasher
import os, email_validator

app = Flask(__name__)

# super secure CSRF key
app.config['SECRET_KEY'] = 'insecureSecretKey123'

# Database
connection = connectDB()
cursor = connection.cursor()

# Password policy settings
minPassLen = 10
minPassUppers = 1
minPassDigits = 1
minPassSpecials = 1

# Password salt generator
def randomSalt():
    return os.urandom(32)

# Password hash generator
def hashGenerator(password, salt):
    hasher = PasswordHasher(hash_len=32)
    hash = hasher.hash(password, salt=salt)
    
    # Verifies that the password matches with the hash
    if(hasher.verify(hash, password)):
        hash = hash.split('$')[5]
        return hash
        
    else:
        print('Password verification error')
        return -1


# WTForms password validator
def validatePassword(form, field):
    uppers = sum(1 for c in field.data if c.isupper())
    digits = sum(1 for c in field.data if c.isdigit())
    specials = 0
    for c in field.data:
        if ord(c) >= 32 and ord(c) <= 47:
            specials += 1
        elif ord(c) >= 58 and ord(c) <= 64:
            specials += 1
        elif ord(c) >= 91 and ord(c) <= 96:
            specials += 1
        elif ord(c) >= 123 and ord(c) <= 126:
            specials += 1
    if len(field.data) < minPassLen:
        print("Minimum password length not met")
        raise ValidationError(f'Password must be at least {minPassLen} characters.')
    elif uppers < minPassUppers:
        print("Minimum password uppercase not met")
        raise ValidationError(f'Password must containt at least {minPassUppers} uppercase letter.')
    elif digits < minPassDigits:
        print("Minimum password digits not met")
        raise ValidationError(f'Password must containt at least {minPassDigits} number.')
    elif specials < minPassSpecials:
        print("Minimum password specials not met")
        raise ValidationError(f'Password must containt at least {minPassSpecials} special character.')
# ====================================================================================== Forms
# Login form
class loginForm(FlaskForm):
    username = StringField("Username: ", validators=[DataRequired()])
    password = StringField("Password: ", validators=[DataRequired()])
    submit = SubmitField("Login")

# Register form
class registerForm(FlaskForm):
    username = StringField("Username: ", validators=[DataRequired()])
    email = EmailField("Email: ", validators=[DataRequired(), Email()])
    password = StringField("Password: ", validators=[DataRequired(), validatePassword])
    submit = SubmitField("Register")


# ====================================================================================== Routes
# Default route
@app.route('/')
def default():
    if session.get('user_id'):
        return redirect(url_for('homepage'))
    else:
        return redirect(url_for('login'))
# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('homepage'))
    else:
        form = loginForm()
        username = None
        password = None
        
        if form.validate_on_submit():
            query = "SELECT username FROM user_credentials WHERE username=%s"
            cursor.execute(query, (form.username.data,))
            user = cursor.fetchone()
            if user is not None:
                query = "SELECT salt, hash FROM user_credentials WHERE username=%s"
                cursor.execute(query, (form.username.data,))
                salt, hash = cursor.fetchone()
                print(f'Salt: {salt}, Hash: {hash}')
                newHash = hashGenerator(form.password.data, salt)
                if newHash == hash:
                    query = "SELECT id FROM user_credentials WHERE username=%s"
                    cursor.execute(query, (form.username.data,))
                    session['user_id'] = cursor.fetchone()
                    session['username'] = form.username.data
                    print(f'Successful login from {user}')
                    return redirect(url_for('homepage'))                          # add an audit log that tracks login attempts & time 
                else:
                    print(f'Failed login attempt for {user}')

        return render_template('login.html', form=form, username=username, password=password)

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user_id'):
        return redirect(url_for('homepage'))
    else:
        form = registerForm()
        username = None
        email = None
        password = None
        salt = randomSalt()
        hash = None

        if form.validate_on_submit():
            query = "SELECT username FROM user_credentials WHERE username=%s"
            cursor.execute(query, (form.username.data,))
            user = cursor.fetchone()
            if user is None:
                query = "SELECT username FROM user_credentials WHERE email=%s"
                cursor.execute(query, (form.email.data,))  # The comma ensures that form.email.data creates a single-element tuple
                email = cursor.fetchone()
                if email is None:
                    username = form.username.data
                    email = form.email.data
                    hash = hashGenerator(form.password.data, salt)
                    query = (" INSERT INTO user_credentials (username, email, salt, hash) VALUES (%s, %s, %s, %s) ")
                    cursor.execute(query, (username, email, salt, hash))
                    connection.commit()
                    print(f'{cursor.rowcount} rows affected.')
                    query = "SELECT id FROM user_credentials WHERE username=%s"
                    cursor.execute(query, (form.username.data,))
                    session['user_id'] = cursor.fetchone()
                    session['username'] = form.username.data
                    print(session.get('user_id'))
                    
                    return redirect(url_for('homepage'))
                else:
                    flash("Error: email not available")
            else:
                flash("Error: username not available")

        return render_template('register.html', form=form, username=username, password=password)

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id')
    return redirect(url_for('login'))

# Homepage route
@app.route('/homepage')
def homepage():
    if session.get('user_id'):
        greeting = f"Hello, {session['username']}."
        flash(greeting)
        return render_template('home.html')
    else:
        return redirect(url_for('login'))

# Main
if __name__ == "__main__":
    app.run(host='127.0.0.1', port=12345, debug=True)
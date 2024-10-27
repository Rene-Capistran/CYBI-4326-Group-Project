from flask import Flask, render_template, redirect, request, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, EmailField, TelField
from wtforms.validators import data_required, ValidationError, email
from password_strength import PasswordPolicy
import argon2

app = Flask(__name__)

# super secure CSRF key
app.config['SECRET_KEY'] = 'insecureSecretKey123'

# Password policy settings
minPassLen = 10
minPassUppers = 1
minPassDigits = 1
minPassSpecials = 1


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
    if len(field.data < minPassLen):
        print("Minimum password length not met")
        raise ValidationError(f'Password must be at least {minPassLen} characters.')
    elif uppers < minPassUppers:
        print("Minimum password uppercase not met")
        raise ValidationError(f'Password must containt at least {minPassUppers} uppercase letter.')
    elif digits < minPassDigits:
        print("Minimum password uppercase not met")
        raise ValidationError(f'Password must containt at least {minPassDigits} number.')
    elif specials < minPassSpecials:
        print("Minimum password uppercase not met")
        raise ValidationError(f'Password must containt at least {minPassSpecials} special character.')
# ====================================================================================== Forms
# Login form
class loginForm(FlaskForm):
    username = StringField("Username: ", validators=[data_required()])
    password = StringField("Password: ", validators=[data_required()])
    submit = SubmitField("Login")

# Register form
class registerForm(FlaskForm):
    username = StringField("Username: ", validators=[data_required()])
    email = EmailField("Email: ", validators=[data_required(), email()])
    password = StringField("Password: ", validators=[data_required(), validatePassword])
    submit = SubmitField("Register")


# ====================================================================================== Routes
# Default route
@app.route('/')
def default():
    if session.get('username'):
        return redirect(url_for('homepage'))
    else:
        return redirect(url_for('login'))
# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('username'):
        return redirect(url_for('homepage'))
    else:
        form = loginForm()
        username = None
        password = None
        return render_template('login.html', form=form, username=username, password=password)

# Logout route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('username'):
        return redirect(url_for('login'))
    else:
        form = registerForm()
        username = None
        password = None
        return render_template('register.html', form=form, username=username, password=password)

# Logout route
@app.route('/logout')
def logout():
    session.pop('username')

# Homepage route
@app.route('/homepage')
def homepage():
    return render_template('home.html')

# Main
if __name__ == "__main__":
    app.run(host='127.0.0.1', port=12345, debug=True)
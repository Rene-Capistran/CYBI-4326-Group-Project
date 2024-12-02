from flask import Flask, render_template, redirect, request, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, EmailField, TelField
from wtforms.validators import DataRequired, ValidationError, Email
from database.db import connectDB
from argon2 import PasswordHasher, low_level
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import timedelta, date
import os

app = Flask(__name__)

# CSRF key
app.config['SECRET_KEY'] = os.environ.get('CSRFtoken')


# Database
connection = connectDB()
cursor = connection.cursor()

# Password policy settings
minPassLen = 10
minPassUppers = 1
minPassDigits = 1
minPassSpecials = 1

MaxUserLen = 30

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

def getIP():
    # Check if the app is behind a proxy
    if 'X-Forwarded-For' in request.headers:
        ip = request.headers['X-Forwarded-For'].split(',')[0]
    else:
        ip = request.remote_addr
    return ip

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
        raise ValidationError(f'Password must be at least {minPassLen} characters.')
    elif uppers < minPassUppers:
        raise ValidationError(f'Password must containt at least {minPassUppers} uppercase letter.')
    elif digits < minPassDigits:
        raise ValidationError(f'Password must containt at least {minPassDigits} number.')
    elif specials < minPassSpecials:
        raise ValidationError(f'Password must containt at least {minPassSpecials} special character.')

def validateUsername(form, field):
    if len(field.data) > MaxUserLen:
        raise ValidationError(f'Username must not exceed 30 characters')
# ====================================================================================== Forms
# Login form
class loginForm(FlaskForm):
    username = StringField("Username: ", validators=[DataRequired()])
    password = StringField("Password: ", validators=[DataRequired()])
    submit = SubmitField("Login")

# Register form
class registerForm(FlaskForm):
    username = StringField("Username: ", validators=[DataRequired(), validateUsername])
    email = EmailField("Email: ", validators=[DataRequired(), Email()])
    password = StringField("Password: ", validators=[DataRequired(), validatePassword])
    confirmPass = StringField("Confirm Password: ", validators=[DataRequired()])
    submit = SubmitField("Register")

# Master set form
class masterSetForm(FlaskForm):
    masterPass = StringField("Master Password: ", validators=[DataRequired(), validatePassword])
    confirmPass = StringField("Confirm Master Password: ", validators=[DataRequired()])
    submit = SubmitField("Set Password")

# Recovery form
class recoveryForm(FlaskForm):
    email = EmailField("Email: ", validators=[DataRequired(), Email()])
    submit = SubmitField("Recover")

# Insert form
class insertForm(FlaskForm):
    account = StringField("Account Name: ", validators=[DataRequired()])
    accountPass = StringField("Account Password: ", validators=[DataRequired()])
    confirmPass = StringField("Confirm Password: ", validators=[DataRequired()])
    masterPass = StringField("Master Password: ", validators=[DataRequired()])
    submit = SubmitField("Add")

# View form
class viewForm(FlaskForm):
    masterPass = StringField("Master Password: ", validators=[DataRequired()])
    submit = SubmitField("Reveal Password")

# Delete form
class deleteForm(FlaskForm):
    masterPass = StringField("Master Password: ", validators=[DataRequired()])
    submit = SubmitField("Remove Credentials")

# Favorites form
class favoriteForm(FlaskForm):
    submit = SubmitField("Add favorite")
# ====================================================================================== Routes
# Default route
@app.route('/')
def default():
    if session.get('user_id'):
        return redirect(url_for('homepage'))
    else:
        return redirect(url_for('login'))
    
# Homepage route
@app.route('/homepage', methods=['GET', 'POST'])
def homepage():
    if session.get('user_id'):
        if not session.get('mp'):
            return redirect(url_for('setmp'))
        else:
            user_id = session.get('user_id')

            # Populate Audit log
            audit_log = []
            query = "SELECT event, event_date, access_ip FROM audit_log WHERE user_id=%s"
            cursor.execute(query, (user_id,))
            events = cursor.fetchall()
            for item in events:
                audit_log.append({'event': item[0], 'date': item[1], 'IP': item[2]})

            # Populate Favorites
            favorites= []
            query = "SELECT account, favorite FROM user_data WHERE user_id=%s"
            cursor.execute(query, (user_id,))
            accounts = cursor.fetchall()
            for item in accounts:
                favorites.append({'account': item[0], 'status': item[1]})

            # Setting date
            current_date = date.today()


 
            greeting = f"Hello, {session['username']}."
            flash(greeting)
            
            
            # Account insertion backend
            insert_form = insertForm()
            if insert_form.validate_on_submit():
                mPass = insert_form.masterPass.data

                query = "SELECT master, masterSalt FROM user_credentials WHERE id=%s"
                cursor.execute(query, (user_id,))
                master, masterSalt = cursor.fetchone()
                newHash = hashGenerator(mPass, masterSalt)
                if newHash == master:
                    account = insert_form.account.data 
                    query = "SELECT salt FROM user_data WHERE user_id=%s AND account=%s"
                    cursor.execute(query, (user_id, account))
                    accSlt = cursor.fetchone()
                    if accSlt is not None:
                        flash('Error: An account under this name already exists')
                    else:
                        # Check for latest iteration
                        currentIteration = 1
                        query = "SELECT MAX(iteration) FROM user_data WHERE user_id = %s"
                        cursor.execute(query, (user_id,))
                        latestIteration = cursor.fetchone()[0]
                        if latestIteration is not None:
                            print(f'Latest iter: {latestIteration}')
                            currentIteration = latestIteration + 1
                        
                    # Encrypting credentials via AES CBC
                        salt = os.urandom(16)
                        iv = os.urandom(16)

                        # using Argon2 to derive a key from the master password
                        key = low_level.hash_secret(master.encode('utf-8'), salt, hash_len=16, time_cost=2, memory_cost=102400, parallelism=8, type=low_level.Type.ID)

                        # Creating the cipher
                        cipher = AES.new(key[:16], AES.MODE_CBC, iv)

                        # Creating the ciphertext
                        ciphertext = cipher.encrypt(pad((insert_form.accountPass.data).encode('utf-8') ,AES.block_size))

                        query = "INSERT INTO user_data (user_id, account, ciphertext, iv, salt, iteration) VALUES (%s, %s, %s, %s, %s, %s)"
                        cursor.execute(query, (user_id, account, ciphertext, iv, salt, currentIteration))
                        connection.commit()

                        query = "INSERT INTO audit_log (user_id, event, access_ip) VALUES (%s, %s, %s)"
                        cursor.execute(query, (user_id, 'added credentials', getIP()))
                        connection.commit()


                        return redirect(url_for('homepage'))



            return render_template('home.html', insert_form=insert_form, auditLog=audit_log, favorites=favorites, date=current_date)
    else:
        return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        if session.get('mp'):
            return redirect(url_for('homepage'))
        else:
            return redirect(url_for('setmp'))
    else:
        form = loginForm()
        username = None
        password = None
        
        if form.validate_on_submit():
            username = form.username.data
            query = "SELECT username FROM user_credentials WHERE username=%s"
            cursor.execute(query, (username,))
            user = cursor.fetchone()
            if user is not None:
                query = "SELECT salt, hash FROM user_credentials WHERE username=%s"
                cursor.execute(query, (username,))
                salt, hash = cursor.fetchone()
                newHash = hashGenerator(form.password.data, salt)
                if newHash == hash:
                    query = "SELECT id FROM user_credentials WHERE username=%s"
                    cursor.execute(query, (username,))
                    session['user_id'] = cursor.fetchone()[0]
                    session['username'] = username
                    
                    query = "SELECT masterSalt FROM user_credentials WHERE username=%s"
                    cursor.execute(query, (username,))
                    mSalt = cursor.fetchone()[0]
                    if mSalt is not None:
                        session['mp'] = 1
                    print(f'Successful login from {user}')

                    # Audit log
                    query = "INSERT INTO audit_log (user_id, event, access_ip) VALUES (%s, %s, %s)"
                    cursor.execute(query, (session.get('user_id'), 'logged in', getIP()))
                    connection.commit()

                    return redirect(url_for('homepage'))
                else:
                    flash('Error: Username or password incorrect')
            else:
                flash('Error: Username or password incorrect')

        return render_template('login.html', form=form, username=username, password=password)

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user_id'):
        if session.get('mp'):
            return redirect(url_for('homepage'))
        else:
            return redirect(url_for('setmp'))
    else:
        form = registerForm()
        username = None
        email = None
        password = None
        confirmPass = None
        salt = randomSalt()
        hash = None

        if form.validate_on_submit():
            print('submitted')
            query = "SELECT username FROM user_credentials WHERE username=%s"
            cursor.execute(query, (form.username.data,))
            user = cursor.fetchone()
            if user is None:
                query = "SELECT username FROM user_credentials WHERE email=%s"
                cursor.execute(query, (form.email.data,))  # The comma ensures that form.email.data creates a single-element tuple
                email = cursor.fetchone()
                if email is None:
                    print('email available')
                    if form.confirmPass.data == form.password.data:
                        username = form.username.data
                        email = form.email.data
                        hash = hashGenerator(form.password.data, salt)
                        query = (" INSERT INTO user_credentials (username, email, salt, hash) VALUES (%s, %s, %s, %s) ")
                        cursor.execute(query, (username, email, salt, hash))
                        connection.commit()
                        print(f'{cursor.rowcount} rows affected.')
                        query = "SELECT id FROM user_credentials WHERE username=%s"
                        cursor.execute(query, (form.username.data,))
                        session['user_id'] = cursor.fetchone()[0]
                        session['username'] = form.username.data
                        session.permanent = False

                        print(session.get('user_id'))
                        
                        return redirect(url_for('homepage'))
                    else:
                        print('Passwords didnt match')
                        flash("Error: Passwords do not match")
                else:
                    flash("Error: Email not available")
            else:
                flash("Error: Username not available")

        return render_template('register.html', form=form, username=username, password=password, confirmPass=confirmPass)
    
# Master password set route
@app.route('/setmp', methods=['GET', 'POST'])
def setmp():
    if session.get('mp'):
        return redirect(url_for('homepage'))
    else:
        form = masterSetForm()
        masterPass = None
        if form.validate_on_submit():
            masterPass = form.masterPass.data
            if masterPass == form.confirmPass.data:
                salt = randomSalt()
                user_id = session.get('user_id')
                masterPassHash = hashGenerator(masterPass, salt)
                query = "UPDATE user_credentials SET master=%s, masterSalt=%s WHERE id=%s"
                cursor.execute(query, (masterPassHash, salt, user_id))
                connection.commit()

                query = "INSERT INTO audit_log (user_id, event, access_ip) VALUES (%s, %s, %s)"
                cursor.execute(query, (user_id, 'set master pass', getIP()))
                connection.commit()

                
                session['mp'] = 1
                return redirect(url_for('homepage'))
            else:
                flash("Error: Passwords do not match")

        return render_template('setmp.html', form=form)
    
# Password list route
@app.route('/passlist', methods=['GET', 'POST'])
def passlist():
    if session.get('user_id'):
        if not session.get('mp'):
            return redirect(url_for('setmp'))
        else:
            user_id = session.get('user_id')
            form = viewForm()
            accList = []
            query = "SELECT account,entry_id FROM user_data WHERE user_id=%s"   #    x, y, z = list
            cursor.execute(query, (user_id,))
            accounts = cursor.fetchall()
            for item in accounts:
                accList.append({'name': item[0], 'id': item[1]})
    else:
        return redirect(url_for('login'))
    
    decrypted_pass = None
    if form.validate_on_submit():
        # Logic to decrypt and reveal password
        print('Validated')
        mPass = form.masterPass.data
        entry_id = request.form.get('entry_id') 

        query = "SELECT master, masterSalt FROM user_credentials WHERE id=%s"
        cursor.execute(query, (user_id,))
        master, masterSalt = cursor.fetchone()
        newHash = hashGenerator(mPass, masterSalt)
        if newHash == master:
            print('Hash matched')
            query = "SELECT ciphertext,iv,salt FROM user_data WHERE entry_id=%s"
            cursor.execute(query, (entry_id,))

            ciphertext, iv, salt = cursor.fetchone()

             # using Argon2 to re-derive the key from the master password
            key = low_level.hash_secret(master.encode('utf-8'), salt, hash_len=16, time_cost=2, memory_cost=102400, parallelism=8, type=low_level.Type.ID)

            # Re-creating the cipher
            cipher = AES.new(key[:16], AES.MODE_CBC, iv)

            # Using the cypher to decrypt the password
            decrypted_pass = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
            
            # Audit log
            query = "INSERT INTO audit_log (user_id, event, access_ip) VALUES (%s, %s, %s)"
            cursor.execute(query, (user_id, 'credentials accessed', getIP()))
            connection.commit()

    return render_template('passlist.html', form=form, accounts=accList, decrypted_pass=decrypted_pass)
# Credential deletion route
@app.route('/delete', methods=['GET', 'POST'])
def delete():
    if session.get('user_id'):
        if not session.get('mp'):
            return redirect(url_for('setmp'))
        else:
            user_id = session.get('user_id')
            form = deleteForm()
            accList = []
            query = "SELECT account,entry_id FROM user_data WHERE user_id=%s"
            cursor.execute(query, (user_id,))
            accounts = cursor.fetchall()
            for item in accounts:
                accList.append({'name': item[0], 'id': item[1]})
    else:
        return redirect(url_for('login'))
    
    if form.validate_on_submit():
        mPass = form.masterPass.data
        entry_id = request.form.get('entry_id') 

        query = "SELECT master, masterSalt FROM user_credentials WHERE id=%s"
        cursor.execute(query, (user_id,))
        master, masterSalt = cursor.fetchone()
        newHash = hashGenerator(mPass, masterSalt)
        if newHash == master:
            query = "DELETE FROM user_data WHERE entry_id=%s"
            cursor.execute(query, (entry_id,))
            connection.commit()

            # Audit log
            query = "INSERT INTO audit_log (user_id, event, access_ip) VALUES (%s, %s, %s)"
            cursor.execute(query, (user_id, 'removed credentials', getIP()))
            connection.commit()

    return render_template('delete.html', form=form, accounts=accList)

@app.route('/favorites', methods=['GET', 'POST'])
def favorite():
    if session.get('user_id'):
        if not session.get('mp'):
            return redirect(url_for('setmp'))
        else:
            user_id = session.get('user_id')
            form = favoriteForm()
            accList = []
            query = "SELECT account,entry_id,favorite FROM user_data WHERE user_id=%s"
            cursor.execute(query, (user_id,))
            accounts = cursor.fetchall()
            for item in accounts:
                accList.append({'name': item[0], 'id': item[1], 'status': item[2]})
    else:
        return redirect(url_for('login'))
    if form.validate_on_submit():
        entry_id = request.form.get('entry_id') 
    
        # Check for current favorite status
        query = "SELECT favorite FROM user_data WHERE entry_id=%s"
        cursor.execute(query, (entry_id,))

        # Inverting favorite setting
        currentFav = cursor.fetchone()
        newFav = not currentFav[0]
        
        print(f"Old favorite setting: {currentFav}    New setting: {newFav}")
        # updating DB
        query = "UPDATE user_data SET favorite=%s WHERE entry_id=%s"
        cursor.execute(query, (newFav, entry_id))
        connection.commit()

    return render_template('favorite.html', form=form, accounts=accList)

    
# Logout route
@app.route('/logout')
def logout():
    session.clear()
    print(f"MP session after logout: {session.get('mp')}")
    return redirect(url_for('login'))

# Recovery route
@app.route('/recover', methods=['GET', 'POST'])
def recover():
    if session.get('user_id'):
        if session.get('mp'):
            return redirect(url_for('homepage'))
        else:
            return redirect(url_for('setmp'))
    else:
        form = recoveryForm()
        email = None
        if form.validate_on_submit():
            query = "SELECT username FROM user_credentials WHERE email=%s"
            cursor.execute(query, (form.email.data,))
            email = cursor.fetchone
            if email is not None:
                print('Insert backend for sending emails')
            flash("If there is an account associated to this email address, a recovery code will be sent to your inbox.")
        return render_template('recover.html', form=form, email=email)

# Main
if __name__ == "__main__":
    app.run(host='127.0.0.1', port=12345, debug=True)
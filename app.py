from flask import Flask, render_template

app = Flask(__name__)

app.config['SECRET_KEY'] = 'insecureSecretKey123'

@app.route('/home')
def homePage():
    return render_template('home.html')

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=12345, debug=True)
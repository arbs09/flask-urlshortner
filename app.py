from flask import Flask, render_template, url_for, send_from_directory
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

@app.route('/')
def index():
    return('Hello World')

@app.route('/dashboard')
def dashboard():
    return('The Dashboard will be here!')



# other

@app.route('/robots.txt')
def robots_txt():
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/.well-known/security.txt')
def security_txt():
    return send_from_directory(app.static_folder, 'security.txt')

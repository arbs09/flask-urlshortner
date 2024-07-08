from flask import Flask, render_template, url_for, send_from_directory, request, redirect
from dotenv import load_dotenv
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["SECRETKEY"]

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

users = []

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/')
def index():
    return('Hello World')


# login, signup and logout
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['user_id']
        
        if user_id in users:
            user = User(user_id)
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='User does not exist. Please try again.')
        
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user_id = request.form['user_id']
        users.append(user_id)
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return ('Logout')

# dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return('The Dashboard will be here!')

# other
@app.route('/robots.txt')
def robots_txt():
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/.well-known/security.txt')
def security_txt():
    return send_from_directory(app.static_folder, 'security.txt')

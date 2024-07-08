from flask import Flask, render_template, url_for, send_from_directory, request, redirect, flash
from dotenv import load_dotenv
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import os
import sqlite3
from hashids import Hashids

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["SECRETKEY"]

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

users = []

hashids = Hashids(min_length=4, salt=app.config['SECRET_KEY'])

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# homepage
@app.route('/')
def index():
    return render_template('index.html')


# shortning
@app.route('/short', methods=('GET', 'POST'))
def short():
    conn = get_db_connection()

    if request.method == 'POST':
        url = request.form['url']

        if not url:
            flash('The URL is required!')
            return redirect(url_for('short'))

        url_data = conn.execute('INSERT INTO urls (original_url) VALUES (?)',
                                (url,))
        conn.commit()
        conn.close()

        url_id = url_data.lastrowid
        hashid = hashids.encode(url_id)
        short_url = request.host_url + hashid

        return render_template('short.html', short_url=short_url)

    return render_template('short.html')

@app.route('/<id>')
def url_redirect(id):
    conn = get_db_connection()

    original_id = hashids.decode(id)
    if original_id:
        original_id = original_id[0]
        url_data = conn.execute('SELECT original_url, clicks FROM urls'
                                ' WHERE id = (?)', (original_id,)
                                ).fetchone()
        original_url = url_data['original_url']
        clicks = url_data['clicks']

        conn.execute('UPDATE urls SET clicks = ? WHERE id = ?',
                     (clicks+1, original_id))

        conn.commit()
        conn.close()
        return redirect(original_url)
    else:
        flash('Invalid URL')
        return redirect(url_for('short'))









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

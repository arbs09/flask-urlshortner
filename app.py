from flask import Flask, render_template, url_for, send_from_directory, request, redirect, flash
from dotenv import load_dotenv
import os
import sqlite3
from hashids import Hashids

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["SECRETKEY"]

hashids = Hashids(min_length=4, salt=app.config['SECRET_KEY'])

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

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
        return redirect(url_for('confirm_redirect', id=id))
    else:
        flash('Invalid URL')
        return redirect(url_for('index'))

@app.route('/confirm/<id>')
def confirm_redirect(id):
    conn = get_db_connection()
    original_id = hashids.decode(id)
    if original_id:
        original_id = original_id[0]
        url_data = conn.execute('SELECT original_url FROM urls'
                                ' WHERE id = (?)', (original_id,)
                                ).fetchone()
        original_url = url_data['original_url']
        conn.close()
        return render_template('confirm.html', original_url=original_url, id=id)
    else:
        flash('Invalid URL')
        return redirect(url_for('index'))

@app.route('/proceed/<id>')
def proceed_redirect(id):
    conn = get_db_connection()
    original_id = hashids.decode(id)
    if original_id:
        original_id = original_id[0]
        url_data = conn.execute('SELECT original_url FROM urls'
                                ' WHERE id = (?)', (original_id,)
                                ).fetchone()
        original_url = url_data['original_url']
        conn.close()
        return redirect(original_url)
    else:
        flash('Invalid URL')
        return redirect(url_for('index'))

# stats
@app.route('/stats')
def stats():
    conn = get_db_connection()
    db_urls = conn.execute('SELECT id, created, original_url, clicks FROM urls').fetchall()
    conn.close()

    urls = []
    for url in db_urls:
        url = dict(url)
        url['short_url'] = request.host_url + hashids.encode(url['id'])
        url['delete_url'] = url_for('delete_url', url_id=url['id'])
        urls.append(url)

    return render_template('stats.html', urls=urls)

@app.route('/delete/<int:url_id>', methods=['GET'])
def delete_url(url_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM urls WHERE id = ?', (url_id,))
    conn.commit()
    conn.close()
    flash('URL deleted successfully', 'success')
    return redirect(url_for('stats'))

# other
@app.route('/robots.txt')
def robots_txt():
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/.well-known/security.txt')
def security_txt():
    return send_from_directory(app.static_folder, 'security.txt')

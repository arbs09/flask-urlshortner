from flask import Flask, render_template, url_for, send_from_directory, request, redirect, flash, make_response
from dotenv import load_dotenv
import os
import sqlite3
from hashids import Hashids
import requests

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["SECRETKEY"]
virustotal_api_key = os.environ["virustotal_api_key"]

hashids = Hashids(min_length=4, salt=app.config['SECRET_KEY'])

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

### URL Checkers
## URLhaus 

def is_url_safe_urlhaus(url):
    response = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url})
    if response.status_code == 200:
        data = response.json()
        if data['query_status'] == 'ok':
            return False  # URL is malicious
        return True  # URL is safe
    return False  # Could not verify, treat as unsafe

## Virustotal

def is_url_safe_virustotal(api_key, url):
    headers = {
        "x-apikey": api_key
    }
    data = {
        "url": url
    }
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    
    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        result_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        if result_response.status_code == 200:
            result_data = result_response.json()["data"]["attributes"]["results"]
            for engine, details in result_data.items():
                if details["category"] in ["malicious", "suspicious"]:
                    return False
            return True
    return False

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

        if (not is_url_safe_virustotal(virustotal_api_key, url)):
            flash('The URL is not safe! by virustotal')
            return redirect(url_for('short'))

        if (not is_url_safe_urlhaus(url)):
            flash('The URL is not safe! by urlhaus')
            return redirect(url_for('short'))
        
        url_data = conn.execute('INSERT INTO urls (original_url) VALUES (?)',
                                (url,))
        conn.commit()
        url_id = url_data.lastrowid
        conn.close()

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
        url_data = conn.execute('SELECT original_url, clicks FROM urls WHERE id = (?)', (original_id,)).fetchone()
        if url_data:
            original_url = url_data['original_url']
            clicks = url_data['clicks']

            conn.execute('UPDATE urls SET clicks = ? WHERE id = ?', (clicks + 1, original_id))
            conn.commit()
            conn.close()
            return redirect(url_for('confirm_redirect', id=id))
        else:
            conn.close()
            flash('URL not found')
            return redirect(url_for('index'))
    else:
        flash('Invalid URL')
        return redirect(url_for('index'))

@app.route('/confirm/<id>')
def confirm_redirect(id):
    conn = get_db_connection()
    original_id = hashids.decode(id)
    if original_id:
        original_id = original_id[0]
        url_data = conn.execute('SELECT original_url, active FROM urls WHERE id = (?)', (original_id,)).fetchone()
        if url_data:
            if url_data['active'] == 1:
                original_url = url_data['original_url']
                conn.close()
                confirmation_token = hashids.encode(original_id)
                resp = make_response(render_template('confirm.html', original_url=original_url, id=id))
                resp.set_cookie('confirmation_token', confirmation_token, httponly=True)
                return resp
            else:
                conn.close()
                flash('Link disabled!')
                return redirect(url_for('index'))
        else:
            conn.close()
            flash('URL not found')
            return redirect(url_for('index'))
    else:
        flash('Invalid URL')
        return redirect(url_for('index'))

# proceed
@app.route('/proceed/<id>')
def proceed_redirect(id):
    conn = get_db_connection()
    original_id = hashids.decode(id)
    if original_id:
        original_id = original_id[0]
        url_data = conn.execute('SELECT original_url, proceed FROM urls WHERE id = (?)', (original_id,)).fetchone()
        if url_data:
            original_url = url_data['original_url']
            proceed = url_data['proceed']

            conn.execute('UPDATE urls SET proceed = ? WHERE id = ?', (proceed + 1, original_id))
            conn.commit()

            confirmation_token = request.cookies.get('confirmation_token')
            expected_token = hashids.encode(original_id)
            
            if confirmation_token == expected_token:
                resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
                resp = make_response(redirect(original_url))
                resp.set_cookie('confirmation_token', '', expires=0, secure=True, httponly=True)
                conn.close()
                return resp
            
            else:
                conn.execute('UPDATE urls SET active = 0 WHERE id = ?', (original_id,))
                conn.commit()
                conn.close()
                flash('Confirmation token does not match and the link is now been deactivated!')
                return redirect(url_for('security'))
        
        else:
            conn.close()
            flash('URL not found')
            return redirect(url_for('index'))
    else:
        flash('Invalid URL')
        return redirect(url_for('index'))

# stats
@app.route('/stats')
def stats():
    conn = get_db_connection()
    db_urls = conn.execute('SELECT id, created, original_url, clicks, proceed FROM urls WHERE active = 1').fetchall()
    conn.close()

    urls = []
    for url in db_urls:
        url = dict(url)
        url['short_url'] = request.host_url + hashids.encode(url['id'])
        #url['delete_url'] = url_for('delete_url', url_id=url['id'])
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

# security
@app.route('/securityalert')
def security():
    return render_template('security.html')

# other
@app.route('/robots.txt')
def robots_txt():
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/.well-known/security.txt')
def security_txt():
    return send_from_directory(app.static_folder, 'security.txt')
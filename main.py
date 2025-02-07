from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from totpy import TOTPAuthenticator
import io
import base64

# Import the app and database functions
from app import app
from db import get_db, init_db

@app.route('/')
def index():
    if session.get('username'):
        return render_template('index.html', username=session['username'])
    return render_template('index.html')

from urllib.parse import urlparse, parse_qs

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

        db = get_db()
        cursor = db.cursor()

        # Check if the username already exists
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            flash("Username already exists!", "danger")
            return redirect(url_for('signup'))

        # Generate a new TOTP secret for the user
        totpy = TOTPAuthenticator()

        # Create a new user record
        password_hash = generate_password_hash(password)
        cursor.execute(
            'INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)',
            (username, password_hash, totpy.get_secret())
        )
        db.commit()

        # Generate TOTP provisioning URI and QR code
        provisioning_uri = totpy.provisioning_uri(username, app.app_name)
        qr_provisioning_uri = totpy.provisioning_uri_qr_code(username, app.app_name)
        img_io = io.BytesIO()
        qr_provisioning_uri.save(img_io, 'PNG')
        img_io.seek(0)
        qr_code = base64.b64encode(img_io.getvalue()).decode('utf-8')

        # Extract the secret key from the provisioning URI
        parsed_url = urlparse(provisioning_uri)
        query_params = parse_qs(parsed_url.query)
        secret_key = query_params.get('secret', [''])[0]

        # Remove padding characters from the secret key
        secret_key = secret_key.rstrip('=')

        # Render the signup success page with the QR code and secret key
        return render_template('signup.html', provisioning_uri=provisioning_uri, qr_code=qr_code, secret_key=secret_key)

    # Render the signup form for GET requests
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user or not check_password_hash(user['password_hash'], password):
            flash("Invalid username or password!", "danger")
            return redirect(url_for('login'))

        # Store username in session temporarily before MFA
        session['pre_2fa_username'] = username
        return redirect(url_for('mfa'))

    # Render the login form for GET requests
    return render_template('login.html')

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    username = session.get('pre_2fa_username')
    if not username:
        flash("Session expired. Please login again.", "danger")
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form.get('token').strip()
        totpy = TOTPAuthenticator(user['totp_secret'])
        if totpy.verify_otp(token):
            session.pop('pre_2fa_username', None)
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash("Invalid token! Please try again.", "danger")
            return redirect(url_for('mfa'))

    # Render the MFA verification form for GET requests
    return render_template('mfa.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

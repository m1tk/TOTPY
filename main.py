from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from totpy import TOTPAuthenticator
import io
import base64
import secrets
import requests

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
        phone    = request.form.get('phone', '').strip() or None

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
            "INSERT INTO users (username, password_hash, totp_secret, phone) VALUES (?, ?, ?, ?)",
            (username, password_hash, totpy.get_secret(), phone)
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
        return redirect(url_for('mfa_choice'))

    # Render the login form for GET requests
    return render_template('login.html')

@app.route('/mfa_choice', methods=['GET', 'POST'])
def mfa_choice():
    username = session.get('pre_2fa_username')
    if not username:
        flash("Session expired. Please login again.")
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if request.method == 'POST':
        method = request.form.get('method')
        if method == 'totp':
            return redirect(url_for('mfa_totp'))
        elif method == 'sms':
            if not user['phone']:
                flash("SMS MFA is not available because phone number was not provided in signup.", "danger")
                return redirect(url_for('mfa_choice'))
            # Generate a random 6-digit code for SMS
            sms_code = str(secrets.randbelow(900000) + 100000)
            session['sms_code'] = sms_code
            try:
                send_sms(user['phone'], sms_code)
            except Exception as e:
                print(e)
                flash("SMS MFA service is not available, please try later.", "danger")
                return redirect(url_for('mfa_choice'))
            return redirect(url_for('mfa_sms'))
        else:
            flash("Invalid MFA method selected.")
            return redirect(url_for('mfa_choice'))
    
    return render_template('mfa_choice.html')

@app.route('/mfa_totp', methods=['GET', 'POST'])
def mfa_totp():
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
    return render_template('mfa_totp.html')

def send_sms(phone, otp):
    print(f"code: {otp}")
    payload = {
        'message': f"TOTPY authentication passcode: {otp}",
        'phoneNumbers': [phone]
    }

    response = requests.post(app.smsgate_server + "/message", auth=app.smsgate_creds, json=payload)
    # Check if the request was successful
    if response.status_code != 202:
        raise Exception()

@app.route('/mfa_sms', methods=['GET', 'POST'])
def mfa_sms():
    username = session.get('pre_2fa_username')
    if not username:
        flash("Session expired. Please login again.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('code').strip()
        if 'sms_code' not in session:
            flash("SMS code expired or not set.", "danger")
            return redirect(url_for('mfa_choice'))
        if code == session.get('sms_code'):
            session.pop('pre_2fa_username', None)
            session.pop('sms_code', None)
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash("Invalid SMS code. Please try again.", "danger")
            return redirect(url_for('mfa_sms'))

    return render_template("mfa_sms.html")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)


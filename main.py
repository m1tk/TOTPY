from flask import render_template_string, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from totpy import TOTPAuthenticator
import io
import base64

from app import app
from db import get_db, init_db

@app.route('/')
def index():
    if session.get('username'):
        return f"Hello, {session['username']}! You are logged in. <br><a href='/logout'>Logout</a>"
    return "Welcome! <a href='/signup'>Signup</a> or <a href='/login'>Login</a>"

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
            flash("Username already exists!")
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

        provisioning_uri    = totpy.provisioning_uri(username, app.app_name)
        qr_provisioning_uri = totpy.provisioning_uri_qr_code(username, app.app_name)
        img_io = io.BytesIO()
        qr_provisioning_uri.save(img_io, 'PNG')
        img_io.seek(0)
        qr_code = base64.b64encode(img_io.getvalue()).decode('utf-8')

        return render_template_string('''
            <h2>Signup Successful!</h2>
            <p>Scan this URL with your authenticator app (e.g., Google Authenticator):</p>
            <p><a href="{{ provisioning_uri }}">{{ provisioning_uri }}</a></p>
            <img src="data:image/png;base64,{{ qr_code }}" alt="QR Code">
            <p>Then <a href="{{ url_for('login') }}">login</a>.</p>
        ''', provisioning_uri=provisioning_uri, qr_code=qr_code)

    return render_template_string('''
        <h2>Signup</h2>
        <form method="post">
            Username: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required><br>
            <input type="submit" value="Sign Up">
        </form>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <p class="{{ category }}">{{ message }}</p>
                {% endfor %}
            {% endif %}
        {% endwith %}
    ''')

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
            flash("Invalid username or password!")
            return redirect(url_for('login'))

        # Store username in session temporarily before MFA
        session['pre_2fa_username'] = username
        return redirect(url_for('mfa'))

    return render_template_string('''
        <h2>Login</h2>
        <form method="post">
            Username: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required><br>
            <input type="submit" value="Login">
        </form>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <p class="{{ category }}">{{ message }}</p>
                {% endfor %}
            {% endif %}
        {% endwith %}
    ''')

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    username = session.get('pre_2fa_username')
    if not username:
        flash("Session expired. Please login again.")
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    if not user:
        flash("User not found!")
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form.get('token').strip()
        totpy = TOTPAuthenticator(user['totp_secret'])
        if totpy.verify_otp(token):
            session.pop('pre_2fa_username', None)
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash("Invalid token! Please try again.")
            return redirect(url_for('mfa'))

    return render_template_string('''
        <h2>MFA Verification</h2>
        <p>Please enter the 6-digit code from your authenticator app.</p>
        <form method="post">
            TOTP Code: <input type="text" name="token" required><br>
            <input type="submit" value="Verify">
        </form>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <p class="{{ category }}">{{ message }}</p>
                {% endfor %}
            {% endif %}
        {% endwith %}
    ''')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)

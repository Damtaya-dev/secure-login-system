import io
import os
import secrets
import time
from functools import wraps
from pathlib import Path

import pyotp
import qrcode
from dotenv import load_dotenv
from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, send_file, session, url_for)

load_dotenv(Path(__file__).with_name('.env'))
from database import ROLES, close_db, get_db, init_db
from security import decrypt_totp, encrypt_totp, hash_password, verify_password

app = Flask(__name__)
for key in ('FLASK_SECRET_KEY', 'PASSWORD_PEPPER', 'TOTP_ENCRYPTION_KEY'):
    if not os.environ.get(key) or os.environ[key].startswith('REPLACE_'):
        raise RuntimeError(f'Missing secure {key}. Run setup.py first.')
app.config.update(SECRET_KEY=os.environ['FLASK_SECRET_KEY'],
                  SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE='Lax',
                  SESSION_COOKIE_SECURE=os.environ.get('RENDER') == 'true',  # localhost HTTP only; set True under HTTPS
                  MAX_CONTENT_LENGTH=16 * 1024)
app.teardown_appcontext(close_db)
init_db()

# In-memory throttling is for a single-process local demo, not production.
attempts = {}

def limited(bucket, key, max_attempts=5, period=300):
    now = time.monotonic()
    token = (bucket, key)
    recent = [t for t in attempts.get(token, []) if now - t < period]
    if len(recent) >= max_attempts:
        attempts[token] = recent
        return True
    recent.append(now)
    attempts[token] = recent
    return False

@app.before_request
def csrf_check():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        provided = request.form.get('csrf_token', '')
        expected = session.get('csrf_token', '')
        if not expected or not secrets.compare_digest(provided, expected):
            abort(400, description='Invalid form token. Reload the page and try again.')

@app.context_processor
def inject_common():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return {'csrf_token': session['csrf_token'], 'current_user': getattr(g, 'user', None)}

@app.before_request
def load_user():
    g.user = None
    uid = session.get('user_id')
    if uid:
        g.user = get_db().execute('SELECT id, username, role FROM users WHERE id=?', (uid,)).fetchone()
        if not g.user: session.clear()

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not g.user: return redirect(url_for('login'))
        return fn(*a, **kw)
    return wrapper

def roles_required(*roles):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*a, **kw):
            # Re-read role from database on each request (not client session).
            if g.user['role'] not in roles: abort(403)
            return fn(*a, **kw)
        return wrapper
    return decorator

@app.route('/')
def index():
    return redirect(url_for('dashboard' if g.user else 'login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if g.user: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        ip = request.remote_addr or 'local'
        if limited('login', ip + ':' + username.lower()):
            flash('Too many attempts. Try again in five minutes.', 'danger')
            return render_template('login.html'), 429
        user = get_db().execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if not user or not verify_password(user['password_hash'], password):
            flash('Invalid username or password.', 'danger')
            return render_template('login.html'), 401
        session.clear()
        session['pending_id'] = user['id']
        session['pending_at'] = time.time()
        session['csrf_token'] = secrets.token_urlsafe(32)
        return redirect(url_for('enroll' if not user['totp_secret'] else 'verify_2fa'))
    return render_template('login.html')

def pending_user():
    uid, at = session.get('pending_id'), session.get('pending_at',0)
    if not uid or time.time()-at > 300:
        session.clear()
        return None
    return get_db().execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()

@app.route('/enroll', methods=['GET','POST'])
def enroll():
    user = pending_user()
    if not user: return redirect(url_for('login'))
    if user['totp_secret']: return redirect(url_for('verify_2fa'))
    if 'enroll_secret' not in session: session['enroll_secret'] = pyotp.random_base32()
    secret = session['enroll_secret']
    if request.method == 'POST':
        code = request.form.get('code','').strip()
        if not pyotp.TOTP(secret).verify(code, valid_window=1):
            flash('Invalid code. Check your phone time and try again.', 'danger')
        else:
            db = get_db()
            db.execute('UPDATE users SET totp_secret=?, totp_last_step=? WHERE id=? AND totp_secret IS NULL', (encrypt_totp(secret),int(time.time())//30,user['id']))
            db.commit()
            session.pop('enroll_secret',None)
            flash('Authenticator linked. Enter a new code to finish login.', 'success')
            return redirect(url_for('verify_2fa'))
    return render_template('enroll.html', secret=secret)

@app.route('/enroll/qr')
def enroll_qr():
    user = pending_user()
    secret = session.get('enroll_secret')
    if not user or user['totp_secret'] or not secret: abort(403)
    uri = pyotp.TOTP(secret).provisioning_uri(name=user['username'], issuer_name='My Web App')
    img = qrcode.make(uri)
    data = io.BytesIO()
    img.save(data, format='PNG')
    data.seek(0)
    response = send_file(data, mimetype='image/png')
    response.headers['Cache-Control'] = 'no-store'
    return response

@app.route('/verify-2fa', methods=['GET','POST'])
def verify_2fa():
    user = pending_user()
    if not user: return redirect(url_for('login'))
    if not user['totp_secret']: return redirect(url_for('enroll'))
    if request.method == 'POST':
        if limited('2fa', str(user['id'])):
            session.clear()
            flash('Too many attempts. Please try again later.', 'danger')
            return redirect(url_for('login'))
        code = request.form.get('code','').strip()
        secret = decrypt_totp(user['totp_secret'])
        totp = pyotp.TOTP(secret)
        now_step = int(time.time()) // totp.interval
        accepted_step = None
        if len(code)==6 and code.isascii() and code.isdigit():
            for step in (now_step-1, now_step, now_step+1):
                if step > user['totp_last_step'] and secrets.compare_digest(totp.at(step*totp.interval),code):
                    accepted_step = step
                    break
        if accepted_step is None:
            flash('Invalid or expired authentication code.', 'danger')
            return render_template('verify_2fa.html'), 401
        db = get_db()
        result = db.execute('UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step<?',
                            (accepted_step,user['id'],accepted_step))
        db.commit()
        if result.rowcount != 1: abort(403)
        session.clear()
        session['user_id'] = user['id']
        session['csrf_token'] = secrets.token_urlsafe(32)
        return redirect(url_for('dashboard'))
    return render_template('verify_2fa.html')

@app.route('/dashboard')
@login_required
def dashboard():
    count = get_db().execute('SELECT COUNT(*) FROM users').fetchone()[0]
    own = get_db().execute('SELECT COUNT(*) FROM records WHERE owner_id=?',(g.user['id'],)).fetchone()[0]
    return render_template('dashboard.html', count=count, own=own)

@app.route('/records', methods=['GET','POST'])
@login_required
def records():
    db = get_db()
    if request.method=='POST':
        content=request.form.get('content','').strip()
        if not (1 <= len(content) <= 500):
            flash('Record must contain 1–500 characters.', 'danger')
        else:
            db.execute('INSERT INTO records (owner_id, content) VALUES (?,?)',(g.user['id'],content))
            db.commit()
            flash('Record saved.', 'success')
            return redirect(url_for('records'))
    rows=db.execute('SELECT * FROM records WHERE owner_id=? ORDER BY id DESC',(g.user['id'],)).fetchall()
    return render_template('records.html', rows=rows)

@app.route('/users')
@roles_required('manager','admin','administrator')
def users():
    rows=get_db().execute('SELECT id,username,role,created_at FROM users ORDER BY id').fetchall()
    return render_template('manage_users.html', rows=rows)

@app.route('/users/add', methods=['GET','POST'])
@roles_required('manager','administrator')
def add_user():
    if request.method=='POST':
        username=request.form.get('username','').strip()
        password=request.form.get('password','')
        role=request.form.get('role','inputer') if g.user['role']=='administrator' else 'inputer'
        if not (3<=len(username)<=30 and username.replace('_','').isalnum()):
            flash('Username must be 3–30 letters, digits or underscores.', 'danger')
        elif len(password)<12:
            flash('Password must be at least 12 characters.', 'danger')
        elif role not in ROLES:
            abort(400)
        else:
            try:
                db=get_db()
                db.execute('INSERT INTO users (username,password_hash,role) VALUES (?,?,?)',
                           (username,hash_password(password),role))
                db.commit()
                flash('Account created. User must enroll their authenticator on first login.', 'success')
                return redirect(url_for('users'))
            except __import__('sqlite3').IntegrityError:
                flash('Username already exists.', 'danger')
    return render_template('add_user.html', roles=ROLES)

@app.route('/users/delete', methods=['GET','POST'])
@roles_required('admin','administrator')
def delete_user():
    db=get_db()
    if request.method=='POST':
        try: uid=int(request.form.get('user_id',''))
        except ValueError: abort(400)
        target=db.execute('SELECT id,role FROM users WHERE id=?',(uid,)).fetchone()
        if not target: abort(404)
        if target['id']==g.user['id']: abort(403)
        if g.user['role']=='admin' and target['role']!='inputer': abort(403)
        if target['role']=='administrator':
            count=db.execute("SELECT COUNT(*) FROM users WHERE role='administrator'").fetchone()[0]
            if count<=1: abort(403)
        db.execute('DELETE FROM users WHERE id=?',(uid,))
        db.commit()
        flash('User deleted.', 'success')
        return redirect(url_for('users'))
    allowed = ('inputer',) if g.user['role']=='admin' else ROLES
    rows=db.execute('SELECT id,username,role FROM users WHERE id!=? ORDER BY username',(g.user['id'],)).fetchall()
    rows=[u for u in rows if u['role'] in allowed]
    return render_template('delete_user.html', rows=rows)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Signed out.', 'success')
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(_): return render_template('access_denied.html'),403
@app.errorhandler(404)
def missing(_): return render_template('error.html',message='Page not found'),404
@app.errorhandler(400)
def bad_request(_): return render_template('error.html',message='Invalid request. Please reload and try again.'),400
@app.errorhandler(413)
def too_large(_): return render_template('error.html',message='Request too large'),413

if __name__=='__main__':
    app.run(host='127.0.0.1',port=5000,debug=False)

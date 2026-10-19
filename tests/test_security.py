import os
import secrets
import tempfile
from pathlib import Path
from cryptography.fernet import Fernet

# Set test environment BEFORE importing the application.
os.environ['FLASK_SECRET_KEY'] = secrets.token_hex(32)
os.environ['PASSWORD_PEPPER'] = secrets.token_hex(32)
os.environ['TOTP_ENCRYPTION_KEY'] = Fernet.generate_key().decode()
_tmp = tempfile.TemporaryDirectory()
os.environ['APP_DB_PATH'] = str(Path(_tmp.name)/'test.db')

import pyotp
from app import app
from database import connect, init_db
from security import hash_password, verify_password, encrypt_totp, decrypt_totp

def csrf(client):
    with client.session_transaction() as s:
        if 'csrf_token' not in s: s['csrf_token'] = secrets.token_urlsafe(32)
        return s['csrf_token']

def create_user(name, role, totp=True):
    secret=pyotp.random_base32()
    with connect() as db:
        db.execute('INSERT INTO users(username,password_hash,role,totp_secret) VALUES(?,?,?,?)',
                   (name,hash_password('LongPassword123!'),role,encrypt_totp(secret) if totp else None))
    return secret

def login_password(client,name):
    return client.post('/login',data={'csrf_token':csrf(client),'username':name,'password':'LongPassword123!'})

def complete_login(client,name,secret):
    response=login_password(client,name)
    assert response.status_code==302
    response=client.post('/verify-2fa',data={'csrf_token':csrf(client),'code':pyotp.TOTP(secret).now()})
    assert response.status_code==302

def test_password_hash():
    hashed=hash_password('LongPassword123!')
    assert verify_password(hashed,'LongPassword123!')
    assert not verify_password(hashed,'incorrect')
    assert hashed!='LongPassword123!'

def test_totp_encryption():
    secret=pyotp.random_base32()
    assert decrypt_totp(encrypt_totp(secret))==secret

def test_protected_routes_and_roles():
    init_db()
    adminsecret=create_user('admin_test','admin')
    create_user('inputer_test','inputer')
    with app.test_client() as client:
        assert client.get('/dashboard').status_code==302
        assert client.get('/users/add').status_code==302
        complete_login(client,'admin_test',adminsecret)
        assert client.get('/dashboard').status_code==200
        assert client.get('/users/add').status_code==403
        assert client.get('/users/delete').status_code==200
        assert client.post('/users/delete',data={'user_id':'2'}).status_code==400  # no CSRF

def test_bad_password_and_2fa():
    secret=create_user('badpass_test','inputer')
    with app.test_client() as client:
        response=client.post('/login',data={'csrf_token':csrf(client),'username':'badpass_test','password':'wrong'})
        assert response.status_code==401
        login_password(client,'badpass_test')
        response=client.post('/verify-2fa',data={'csrf_token':csrf(client),'code':'000000'})
        assert response.status_code==401
        assert client.get('/dashboard').status_code==302
        response=client.post('/verify-2fa',data={'csrf_token':csrf(client),'code':pyotp.TOTP(secret).now()})
        assert response.status_code==302
        assert client.get('/dashboard').status_code==200

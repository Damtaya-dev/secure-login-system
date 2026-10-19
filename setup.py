import getpass
import os
import secrets
from pathlib import Path
from cryptography.fernet import Fernet
from dotenv import load_dotenv

ROOT=Path(__file__).parent
ENV=ROOT/'.env'
if not ENV.exists():
    ENV.write_text('FLASK_SECRET_KEY='+secrets.token_hex(32)+'\nPASSWORD_PEPPER='+secrets.token_hex(32)+'\nTOTP_ENCRYPTION_KEY='+Fernet.generate_key().decode()+'\n')
    print('Created private .env file.')
load_dotenv(ENV)
from database import connect, init_db
from security import hash_password
init_db()
with connect() as db:
    if db.execute('SELECT COUNT(*) FROM users').fetchone()[0]:
        print('Accounts already exist. No changes made.')
    else:
        print('Create four demonstration accounts. Use different passwords (12+ characters).')
        for role in ('administrator','manager','admin','inputer'):
            username=role+'_demo'
            while True:
                password=getpass.getpass(f'Choose password for {username}: ')
                if len(password)>=12: break
                print('At least 12 characters required.')
            db.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',
                       (username,hash_password(password),role))
            db.commit()
        print('Accounts created. Enroll Google Authenticator on first login.')
print('Setup complete. Start with: python app.py')

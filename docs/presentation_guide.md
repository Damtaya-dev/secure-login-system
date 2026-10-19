# Five-minute demonstration guide

1. Explain the objective: identification, authentication, 2FA, and role-based authorization.
2. Show login. Enter wrong password: generic rejection. Enter correct password: 2FA required.
3. Demonstrate Google Authenticator enrollment for a new demo account, then TOTP login.
4. Show the dashboard and a sample record.
5. Log in as manager: create an inputer. Show that manager cannot delete users.
6. Log in as admin: delete an inputer. Show admin cannot add users or delete higher roles.
7. Log in as administrator: show both actions and role selection.
8. Explain salted Argon2id hashes, pepper in .env, encrypted TOTP keys, CSRF tokens, SQLite parameterized queries, local server and limitations.

## Likely questions
**What is identification?** Providing a username to identify the account.
**Authentication?** Proving identity with a password and an independent TOTP code.
**Authorization?** Enforcing allowed actions based on the role stored in the database.
**Salt vs pepper?** Argon2id generates a unique salt per hash; a separate application-wide secret pepper is kept outside the database.
**Why SQLite?** Simple file-based offline relational database for a local prototype.
**Why 2FA?** A stolen password alone is insufficient to sign in.
**What is CSRF?** A forged request from another site; a per-session form token helps reject it.
**Is this production-ready?** No. It is a local coursework demonstration; HTTPS, persistent throttling, audit logging, hardened sessions and operational controls are still needed.
**Does GitHub host the running app?** No. It hosts source code; users follow README to run it locally.

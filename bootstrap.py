import os
from database import init_db, connect
from security import hash_password

init_db()

password = os.environ.get("DEMO_ADMIN_PASSWORD")

if not password or len(password) < 12:
    raise RuntimeError(
        "DEMO_ADMIN_PASSWORD must contain at least 12 characters."
    )

with connect() as db:
    existing = db.execute(
        "SELECT id FROM users WHERE username = ?",
        ("administrator_demo",)
    ).fetchone()

    if not existing:
        db.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
            """,
            (
                "administrator_demo",
                hash_password(password),
                "administrator"
            )
        )
        db.commit()
        print("Demo administrator created successfully.")
    else:
        print("Demo administrator already exists.")

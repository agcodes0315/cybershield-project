import sqlite3
import bcrypt

NEW_PASSWORD = "CyberShield2026!"

password_hash = bcrypt.hashpw(
    NEW_PASSWORD.encode("utf-8"),
    bcrypt.gensalt()
).decode("utf-8")

conn = sqlite3.connect("gophish.db")
cur = conn.cursor()

cur.execute(
    """
    UPDATE users
    SET hash = ?,
        password_change_required = 0,
        account_locked = 0
    WHERE username = 'admin'
    """,
    (password_hash,)
)

conn.commit()

print(f"Updated users: {cur.rowcount}")
print("Admin password reset successfully.")

conn.close()

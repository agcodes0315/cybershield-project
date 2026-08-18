import sqlite3

conn = sqlite3.connect("gophish.db")
cur = conn.cursor()

print("TABLES:")
print(cur.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
).fetchall())

print("\nUSERS SCHEMA:")
print(cur.execute(
    "PRAGMA table_info(users)"
).fetchall())

print("\nUSERS:")
print(cur.execute(
    "SELECT id, username FROM users"
).fetchall())

conn.close()

"""
API routes with intentional SQL injection sink (fixture only — do not deploy).
"""


def search_users(db_cursor, q: str):
    # INTENTIONALLY VULNERABLE — mono_synth fixture
    sql = f"SELECT * FROM users WHERE name = '{q}'"
    return db_cursor.execute(sql)


def get_item(db_cursor, item_id: str):
    # INTENTIONALLY VULNERABLE — mono_synth fixture
    return db_cursor.execute(f"SELECT * FROM items WHERE id = {item_id}")

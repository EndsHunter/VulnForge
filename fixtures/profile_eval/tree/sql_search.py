"""Intentional SQLi fixture for hunt-profile eval. Do not deploy."""

def search_users(db_cursor, q: str):
    sql = f"SELECT * FROM users WHERE name = '{q}'"
    return db_cursor.execute(sql)

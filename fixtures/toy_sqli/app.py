"""
Tiny intentional SQLi fixture for harness end-to-end tests later.

WARNING: deliberately vulnerable — do not deploy.
"""

# TODO: expand into minimal Flask/FastAPI app with known SQLi for integration tests

def search_users(db_cursor, q: str):
    # INTENTIONALLY VULNERABLE — fixture only
    sql = f"SELECT * FROM users WHERE name = '{q}'"
    return db_cursor.execute(sql)

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

# mutated

def lookup_user(conn, name):
    sql = "SELECT id FROM users WHERE name = ?"
    return conn.execute(sql, (name,))

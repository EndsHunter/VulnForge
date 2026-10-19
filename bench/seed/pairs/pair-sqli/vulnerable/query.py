def lookup_user(conn, name):
    sql = "SELECT id FROM users WHERE name = '" + name + "'"
    return conn.execute(sql)

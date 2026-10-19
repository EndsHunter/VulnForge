def allow(supplied, stored):
    if not supplied or not stored:
        return False
    return supplied == stored

def require_auth(req):
    return bool(req.get('token'))

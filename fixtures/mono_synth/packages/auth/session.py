"""Session / token helpers (fixture stub — not production auth)."""


def issue_token(user_id: str, secret: str = "dev-secret") -> str:
    # Weak signing for fixture realism only
    return f"{user_id}:{secret}"


def verify_token(token: str, secret: str = "dev-secret") -> bool:
    return token.endswith(f":{secret}")

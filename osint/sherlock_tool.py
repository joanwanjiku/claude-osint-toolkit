from osint.validation import is_valid_username, resolve_site_alias, list_sites

def check_username(username: str, sites: list = None) -> dict:
    """
    Check the validity of a username and resolve site aliases.
    Args:
        username (str): The username to check.
    Returns:
        dict: A dictionary containing the validity status and resolved site information.
    """
    if not is_valid_username(username):
        return {"status": "error", "reason": f"'{username}' is not a valid username format."}

    if sites is None:                       # no sites given → full scan, nothing to resolve
        return {"status": "ok", "username": username, "sites": None}

    resolved, unknown, nsfw = resolve_site_alias(sites)   # site names, not the username
    if unknown or nsfw:
        return {
            "status": "error",
            "reason": "some requested sites can't be scanned; nothing was run",
            "unknown_sites": unknown,
            "nsfw_excluded": nsfw,
        }
    return {"status": "ok", "username": username, "sites": resolved}
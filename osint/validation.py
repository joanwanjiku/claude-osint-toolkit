
import re
from importlib.resources import files
import json
import difflib

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,49}$")
site_alias = {"x":"twitter"}


def is_valid_username(username: str) -> bool:
    """
    Validate the format of a username.
    Args:
        username (str): The username to validate.
    Returns:
        bool: True if the username format is valid, False otherwise.
    """
    return bool(USERNAME_RE.match(username))

def load_sherlock_data() -> dict:
    """
    Load the sherlock data from the data.json file.
    Returns:
        dict: A dictionary containing the sherlock data.
    """
    data_file = files("sherlock_project") / "resources" / "data.json"
    data = json.loads(data_file.read_text(encoding="utf-8"))
    sites = {name.lower(): name for name in data if not name.startswith("$")}
    nsfw = {name.lower() for name, info in data.items()
            if isinstance(info, dict) and info.get("isNSFW")}
    return sites, nsfw

SHERLOCK_SITES, SHERLOCK_NSFW = load_sherlock_data()

def resolve_site_alias(sites):
    """
    Match requested site names against Sherlock's site list, case-insensitively.
    Args:
        sites (list[str]): Site names as given by the caller.
    Returns:
        tuple: (resolved real names without duplicates,
                {unknown name: close-match suggestions},
                NSFW sites that Sherlock would silently skip)
    """
    resolved, unknown, nsfw = [], {}, []
    for raw in sites:
        key = raw.strip().lower()
        key = site_alias.get(key, key)
        if key not in SHERLOCK_SITES:
            matches = difflib.get_close_matches(key, SHERLOCK_SITES, n=3, cutoff=0.6)
            unknown[raw] = [SHERLOCK_SITES[m] for m in matches]
        elif key in SHERLOCK_NSFW:
            nsfw.append(SHERLOCK_SITES[key])
        elif SHERLOCK_SITES[key] not in resolved:
            resolved.append(SHERLOCK_SITES[key])
    return resolved, unknown, nsfw

def list_sites(query: str = "") -> list[str]:
    """
    List Sherlock site names (excluding NSFW), optionally filtered by substring.
    Args:
        query (str): Case-insensitive substring to filter by; empty returns all.
    Returns:
        list[str]: Matching real site names, sorted.
    """
    q = query.strip().lower()
    return sorted(name for key, name in SHERLOCK_SITES.items()
                  if q in key and key not in SHERLOCK_NSFW)

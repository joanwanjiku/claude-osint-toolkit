import asyncio
import httpx
import os
import re
from urllib.parse import quote

USER_AGENT = "claudeosint/0.1"  # HIBP requires an honest user-agent identifying the app
HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
MAX_RETRY_WAIT = 10  # seconds; longer 429 waits are returned to the caller instead

def is_valid_email(email: str) -> bool:
    """
    Validate the email format using a regular expression.
    Args:
        email (str): The email address to validate.
    Returns:
        bool: True if the email format is valid, False otherwise.
    """
    email_regex = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$")
    return bool(email_regex.match(email))

async def make_hibp_request(email: str) -> dict:
    """
    Make an asynchronous request to the Have I Been Pwned API.
    Args:
        email (str): The email address to query.
    Returns:
        dict: A dictionary containing the response from the Have I Been Pwned API.
    """
    email = email.strip()
    if not is_valid_email(email):
        return {"status": "error", "reason": f"'{email}' is not a valid email address"}

    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        return {"status": "error", "reason": "HIBP_API_KEY is not set"}

    headers = {
        "user-agent": USER_AGENT,
        "hibp-api-key": api_key,
    }
    url = f"{HIBP_BASE_URL}/breachedaccount/{quote(email, safe='')}"
    params = {"truncateResponse": "false"}

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(url, headers=headers, params=params)
            if response.status_code == 429:
                wait = int(response.headers.get("retry-after", MAX_RETRY_WAIT + 1))
                if wait > MAX_RETRY_WAIT:
                    return {"status": "error", "reason": f"HIBP rate limit hit; retry in {wait}s"}
                await asyncio.sleep(wait)
                response = await client.get(url, headers=headers, params=params)
    except httpx.HTTPError as e:
        return {"status": "error", "reason": f"network error: {e}"}

    if response.status_code == 200:
        return format_hibp_output(email, response.json())
    if response.status_code == 404:
        return {"status": "not_found", "email": email}
    if response.status_code == 401:
        return {"status": "error", "reason": "invalid HIBP API key"}
    if response.status_code == 429:
        return {"status": "error", "reason": "HIBP rate limit hit; try again shortly"}
    return {"status": "error", "reason": f"HTTP {response.status_code}"}

def format_hibp_output(email: str, data: list) -> dict:
    """
    Trim the Have I Been Pwned breach list to the fields useful for analysis.
    Args:
        email (str): The email address that was queried.
        data (list): The list of breach objects from the Have I Been Pwned API.
    Returns:
        dict: A summary plus one trimmed entry per breach.
    """
    breaches = [
        {
            "name": b.get("Name"),
            "title": b.get("Title"),
            "domain": b.get("Domain"),
            "breach_date": b.get("BreachDate"),
            "pwn_count": b.get("PwnCount"),
            "data_classes": b.get("DataClasses", []),
            "is_verified": b.get("IsVerified"),
            "is_sensitive": b.get("IsSensitive"),
            "is_spam_list": b.get("IsSpamList"),
        }
        for b in data
    ]
    dates = sorted(b["breach_date"] for b in breaches if b["breach_date"])
    return {
        "status": "breached",
        "email": email,
        "breach_count": len(breaches),
        "earliest_breach": dates[0] if dates else None,
        "latest_breach": dates[-1] if dates else None,
        "data_classes_exposed": sorted({dc for b in breaches for dc in b["data_classes"]}),
        "breaches": breaches,
    }

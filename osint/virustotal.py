import httpx
import os
import re

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.3"
VT_BASE_URL = "https://www.virustotal.com/api/v3/"
DOMAIN_REGEX = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
VT_API_KEY = os.getenv("VT_API_KEY")

def normalize_url(url: str) -> str | None:
    """
    Normalize a URL by ensuring it has a scheme and removing any trailing slashes.
    Args:
        url (str): The URL to normalize.
    """
    d = url.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split(":")[0].rstrip(".")
    return d if DOMAIN_REGEX.match(d) else None

async def make_vrt_request(domain: str):
    """
    Make an asynchronous request to the VirusTotal API.
    Args:
        domain (str): The domain to query.
    Returns:
        dict: A dictionary containing the response from the VirusTotal API.
    """
    cleaned_domain = normalize_url(domain)
    if cleaned_domain is None:
        return {"error": "Invalid domain format", "reason": "Please provide a domain like 'example.com'."}
    
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{VT_BASE_URL}domains/{cleaned_domain}", headers=headers)
    except httpx.RequestError as e:
        return {"error": f"Request error: {str(e)}", "status_code": 500}

    if response.status_code == 200:
        return format_vrt_output(response.json())
    else:
        return {"error": "Failed to retrieve information", "status_code": response.status_code}
    
            
def format_vrt_output(data: dict) -> str:
    """
    Format the output from the VirusTotal API for better readability.
    Args:
        data (dict): The response data from the VirusTotal API.
    Returns:
        str: A formatted string representation of the data.
    """
    attrs = data["data"]["attributes"]
    results = attrs.get("last_analysis_results", {})
    flagged = [
        engine for engine, result in results.items() if result.get("category") in ("malicious", "suspicious")
    ]
    return  {
        "status": "ok",
        "domain": data["data"]["id"],
        "stats": attrs.get("last_analysis_stats", {}),
        "reputation": attrs.get("reputation"),
        "categories": sorted(set(attrs.get("categories", {}).values())),
        "flagged_by": flagged[:10],
        "registrar": attrs.get("registrar"),
        "creation_date": attrs.get("creation_date"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "permalink": f"https://www.virustotal.com/gui/domain/{data['data']['id']}",
    }
    



from pathlib import Path
from typing import Optional, List, Dict, Any

from dotenv import load_dotenv

from osint.hibp import make_hibp_request

# Load .env before importing osint modules: they read env vars at import time.
load_dotenv(Path(__file__).resolve().parent / ".env")

import httpx
from mcp.server.mcpserver import MCPServer as Server
from mcp.types import ToolAnnotations
from osint.virustotal import make_vrt_request
from osint.sherlock_tool import check_username

mcp = Server(
    name="claudeosint",
    description="A tool for OSINT and information gathering.",
    version="1.0.0",
)
@mcp.tool()
async def vt_domain_report(domain: str) -> Dict[str, Any]:
    """Look up a domain's reputation on virustotal
    Pass a bare domain like "example.com" (URLs are accepted and stripped).
    Returns detection stats (malicious/suspicious/harmless/undetected),
    reputation score, categories, engines that flagged it, and registrar info.
    status "not_found" means VirusTotal has no record, not that it is safe.
    """
    return await make_vrt_request(domain)


@mcp.tool()
async def email_breach_report(email: str) -> Dict[str, Any]:
    """Look up an email address on haveibeenpwned.com
    Pass a valid email address like "
    """
    return await make_hibp_request(email)

@mcp.tool()
async def check_inputs(username: str, sites: list = None) -> Dict[str, Any]:
    """Check the validity of a username and resolve site aliases.
    Pass a username like "exampleuser" (no @ or URL).
    Returns a dict with validity status, resolved site names, unknown sites with suggestions,
    and NSFW sites that Sherlock would skip.
    """
    return check_username(username, sites)

def main():
    mcp.run(transport="stdio")
    

if __name__ == "__main__":
    main()

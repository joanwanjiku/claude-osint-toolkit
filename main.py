from pathlib import Path
from typing import Optional, List, Dict, Any

from dotenv import load_dotenv

from osint.hibp import make_hibp_request

# Load .env before importing osint modules: they read env vars at import time.
load_dotenv(Path(__file__).resolve().parent / ".env")

import httpx
from mcp.server.mcpserver import Context, MCPServer as Server
from mcp.types import ToolAnnotations
from osint.virustotal import get_vrt_file_hash, make_vrt_request
from osint.sherlock_tool import run_sherlock
from osint.validation import list_sites

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

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
async def sherlock_username_search(
    username: str, sites: Optional[List[str]] = None, ctx: Context = None
) -> Dict[str, Any]:
    """Search for a username across websites with Sherlock.

    Pass one username without @ (e.g. "torvalds"). Pass `sites` for a targeted
    scan (e.g. ["GitHub", "Reddit", "Instagram"]), which takes a few seconds;
    omit it to scan all ~460 sites, which takes 20-60 seconds. Use
    list_sherlock_sites to find exact site names.

    Results are POSSIBLE accounts, not confirmed ones: Sherlock has a high
    false-positive rate, so present them that way and suggest checking the URLs.
    Sites listed in `skipped` were not checked; don't report them as "not found".
    status "partial" means the scan timed out and the results are incomplete.
    """
    async def on_progress(checked: int, total: int) -> None:
        if ctx is not None:
            await ctx.report_progress(checked, total, f"checked {checked} of {total} sites")

    return await run_sherlock(username, sites, on_progress=on_progress)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def list_sherlock_sites(query: str = "") -> List[str]:
    """List site names Sherlock can check, filtered by a case-insensitive substring.

    Call this before a targeted sherlock_username_search to get exact site
    names (e.g. query "git" -> GitHub, GitLab, Gitea...). Empty query lists all.
    """
    return list_sites(query)

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
async def get_file_hash_info(hash: str) -> Dict[str, Any]:
    """Look up a file hash on VirusTotal.

    Pass a valid hash (MD5, SHA1, or SHA256). Returns detection stats
    (malicious/suspicious/harmless/undetected), reputation score, categories,
    engines that flagged it, and a permalink to the VT report.
    status "not_found" means VirusTotal has no record, not that it is safe.
    """
    return await get_vrt_file_hash(hash)

def main():
    mcp.run(transport="stdio")
    

if __name__ == "__main__":
    main()

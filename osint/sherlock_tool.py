import asyncio
import csv
import sys
import tempfile
import time
from pathlib import Path
from typing import Awaitable, Callable

from osint.validation import (
    SHERLOCK_NSFW,
    SHERLOCK_SITES,
    is_valid_username,
    resolve_site_alias,
)

SHERLOCK_BIN = Path(sys.executable).parent / "sherlock"  # the venv's own sherlock
SITE_TIMEOUT = 10      # seconds Sherlock waits for each site
SCAN_TIMEOUT = 120     # seconds before the whole scan is killed
PROGRESS_EVERY = 25    # report progress after this many sites

ProgressCallback = Callable[[int, int], Awaitable[None]]


def check_username(username: str, sites: list = None) -> dict:
    """
    Validate the username and resolve requested site names before a scan.
    Args:
        username (str): The username to search for.
        sites (list[str] | None): Site names to scan; None means all sites.
    Returns:
        dict: status "ok" with the real site names to scan and any skipped
              sites, or status "error" with the reason.
    """
    if not is_valid_username(username):
        return {"status": "error", "reason": f"'{username}' is not a valid username format."}

    if sites is None:                       # no sites given → full scan, nothing to resolve
        return {"status": "ok", "username": username, "sites": None, "skipped": {}}

    resolved, unknown, nsfw = resolve_site_alias(sites)   # site names, not the username

    # Likely typos: stop so the caller can fix the name and retry.
    typos = {name: hints for name, hints in unknown.items() if hints}
    if typos:
        return {
            "status": "error",
            "reason": "unrecognised site names; nothing was run",
            "did_you_mean": typos,
        }

    # Unsupported or NSFW sites: skip them, scan the rest, and say so.
    skipped = {name: "not supported by Sherlock" for name in unknown}
    skipped.update({name: "NSFW site, excluded" for name in nsfw})

    if not resolved:
        return {
            "status": "error",
            "reason": "none of the requested sites can be scanned",
            "skipped": skipped,
        }
    return {"status": "ok", "username": username, "sites": resolved, "skipped": skipped}


def _build_args(username: str, sites: list[str] | None, out_dir: str) -> list[str]:
    """
    Build Sherlock's argument list. A list (never a shell string) means the
    username can't inject shell commands; "--" stops it being read as a flag.
    """
    args = [
        str(SHERLOCK_BIN),
        "--local",            # bundled site list: no download, same result every run
        "--no-color",
        "--print-all",        # one line per site checked, used for progress
        "--csv",
        "--folderoutput", out_dir,
        "--timeout", str(SITE_TIMEOUT),
    ]
    for site in sites or []:
        args += ["--site", site]
    args += ["--", username]
    return args


def _parse_csv(csv_path: Path) -> list[dict]:
    """
    Read Sherlock's CSV and keep only the sites where the username was found.
    Returns:
        list[dict]: [{"site": ..., "url": ...}] sorted by site name.
    """
    if not csv_path.exists():
        return []
    with csv_path.open(newline="", encoding="utf-8") as f:
        rows = csv.DictReader(f)
        found = [{"site": r["name"], "url": r["url_user"]}
                 for r in rows if r.get("exists") == "Claimed"]
    return sorted(found, key=lambda a: a["site"].lower())


def _parse_found_line(line: str) -> dict | None:
    """
    Parse a "[+] Site: url" stdout line. Only used for partial results after
    a timeout, because Sherlock writes the CSV when it finishes.
    """
    if not line.startswith("[+] "):
        return None
    site, _, url = line[4:].partition(": ")
    return {"site": site, "url": url} if url else None


async def run_sherlock(
    username: str,
    sites: list[str] | None = None,
    on_progress: ProgressCallback | None = None,
    scan_timeout: float = SCAN_TIMEOUT,
) -> dict:
    """
    Search for a username with Sherlock and return the possible accounts found.
    Args:
        username (str): The username to search for.
        sites (list[str] | None): Site names to scan; None scans every site.
        on_progress (callable | None): Awaited with (sites_checked, total).
        scan_timeout (float): Seconds before the scan is killed.
    Returns:
        dict: status ("ok", "partial" or "error"), the accounts found and
              any sites that were skipped.
    """
    checked = check_username(username, sites)
    if checked["status"] != "ok":
        return checked
    sites, skipped = checked["sites"], checked["skipped"]
    total = len(sites) if sites else len(SHERLOCK_SITES) - len(SHERLOCK_NSFW)

    if not SHERLOCK_BIN.exists():
        return {"status": "error", "reason": f"sherlock not found at {SHERLOCK_BIN}"}

    started = time.monotonic()
    with tempfile.TemporaryDirectory() as out_dir:
        proc = await asyncio.create_subprocess_exec(
            *_build_args(username, sites, out_dir),
            stdin=asyncio.subprocess.DEVNULL,   # stdin/stdout carry Claude's messages
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=out_dir,
        )
        lines: list[str] = []

        async def read_stdout() -> None:
            sites_done = 0
            async for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").strip()
                lines.append(line)
                if line.startswith(("[+] ", "[-] ")):
                    sites_done += 1
                    if on_progress and sites_done % PROGRESS_EVERY == 0:
                        await on_progress(sites_done, total)

        try:
            # Drain stderr alongside stdout so a full pipe can't stall Sherlock.
            await asyncio.wait_for(
                asyncio.gather(read_stdout(), proc.stderr.read(), proc.wait()),
                timeout=scan_timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            accounts = [a for a in map(_parse_found_line, lines) if a]
            return {
                "status": "partial",
                "reason": f"scan stopped after {scan_timeout:.0f}s; results are incomplete",
                "username": username,
                "found_count": len(accounts),
                "accounts": accounts,
                "skipped": skipped,
                "note": "Unverified: Sherlock has a high false-positive rate.",
            }

        if proc.returncode != 0:
            errors = [l for l in lines if l.startswith("Error:")]
            return {"status": "error",
                    "reason": errors[0] if errors else f"sherlock exited with code {proc.returncode}"}

        accounts = _parse_csv(Path(out_dir) / f"{username}.csv")

    return {
        "status": "ok",
        "username": username,
        "sites_checked": total,
        "found_count": len(accounts),
        "accounts": accounts,
        "skipped": skipped,
        "duration_s": round(time.monotonic() - started, 1),
        "note": "Unverified: Sherlock has a high false-positive rate.",
    }

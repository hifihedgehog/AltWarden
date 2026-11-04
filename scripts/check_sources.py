"""Ask every network list source whether it still answers. A moved list would otherwise fail on servers only.

    python scripts/check_sources.py
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aiohttp

from altwarden.netintel import SOURCES


async def status(session: aiohttp.ClientSession, name: str, url: str) -> tuple[str, int | str]:
    try:
        async with session.head(url, allow_redirects=True, headers={"User-Agent": "AltWarden list refresh"}) as response:
            return name, response.status
    except aiohttp.ClientError as error:
        return name, type(error).__name__


async def main() -> int:
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        results = await asyncio.gather(*(status(session, name, url) for name, url in SOURCES.items()))
    failed = [result for result in results if result[1] != 200]
    print(f"{len(results) - len(failed)} of {len(results)} sources answered")
    for name, answer in failed:
        print(f"  {name}: {answer}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

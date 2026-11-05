"""List every member-facing English string in altwarden/web/static/i18n/en.json, for translators."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from altwarden.catalog import FAILURE_TEXT
from altwarden.ports import DISCORD_BUSY

JS = ROOT / "altwarden" / "web" / "static" / "js"
STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
CALL = re.compile(r'\b(?:t|line)\("((?:[^"\\]|\\.)*)"')  # line() in mydata.js translates its label
KINDS = re.compile(r'(?:ip|cookie|fingerprint|device|os|browser): "([^"]+)"')
SINGLE_WORDS = {"Reload", "Status", "Sent", "Deleted.", "Checking…", "Checking", "Done", "Verified", "Joined"}
SERVICE = ROOT / "altwarden" / "service.py"
APP = ROOT / "altwarden" / "web" / "app.py"
# What the server sends for the page to show: a problem's title and text, the help desk's refusals, and API errors.
PROBLEM = re.compile(r'Result\("problem", "([^"]+)", "([^"]+)"')
REFUSAL = re.compile(r'return None, "([^"]+)"')
API_ERROR = re.compile(r'json_error\(\d+, "([^"]+)"')
# Why an appeal is refused: submit_appeal's answers to the page, and _appeal_problem's, which the page also shows before anyone types.
APPEAL_CODE = re.compile(r"async def submit_appeal.*?async def appeal_state", re.DOTALL)
APPEAL_REFUSAL = re.compile(r'(?:return|return last,|else) "([^"]+)"')


def main() -> None:
    found: list[str] = []
    for name in ("verify.js", "mydata.js", "appeal.js", "help.js"):
        found += CALL.findall((JS / name).read_text(encoding="utf-8"))
    help_text = (JS / "help.js").read_text(encoding="utf-8")
    block = help_text[help_text.index("const STAFF"):help_text.index("const titles")]
    found += [value for value in STRING.findall(block) if " " in value]
    found += KINDS.findall((JS / "mydata.js").read_text(encoding="utf-8"))
    found += list(FAILURE_TEXT.values())
    found += ["Please sign in again", "This server's rules changed, so Discord needs to confirm your account again.",  # sent by the server
              "Almost there", "You passed, but the server's roles need fixing. Staff have been told.",
              "You passed, but the server's roles need fixing. Please tell the server's staff.",
              "You passed, but Discord didn't answer. Try again in a moment.", DISCORD_BUSY,
              "The help desk can't open a thread right now. Staff have been told.", "The help desk can't open a thread right now. Please tell the server's staff."]
    service = SERVICE.read_text(encoding="utf-8")
    found += [text for pair in PROBLEM.findall(service) for text in pair]
    found += REFUSAL.findall(service)
    found += APPEAL_REFUSAL.findall(APPEAL_CODE.search(service).group(0))
    found += API_ERROR.findall(APP.read_text(encoding="utf-8"))
    unique = list(dict.fromkeys(value for value in found if " " in value or value in SINGLE_WORDS))
    target = ROOT / "altwarden" / "web" / "static" / "i18n" / "en.json"
    target.write_text(json.dumps(unique, ensure_ascii=False, indent=0), encoding="utf-8")
    print(len(unique), "strings,", sum(map(len, unique)), "characters")


if __name__ == "__main__":
    main()

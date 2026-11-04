"""List every member-facing English string in altwarden/web/static/i18n/en.json, for translators."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from altwarden.catalog import FAILURE_TEXT

JS = ROOT / "altwarden" / "web" / "static" / "js"
STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
CALL = re.compile(r'\bt\("((?:[^"\\]|\\.)*)"')
KINDS = re.compile(r'(?:ip|cookie|fingerprint|device|os|browser): "([^"]+)"')
SINGLE_WORDS = {"Reload", "Status", "Sent", "Deleted.", "Checking…", "Checking"}


def main() -> None:
    found: list[str] = []
    for name in ("verify.js", "mydata.js", "appeal.js", "help.js"):
        found += CALL.findall((JS / name).read_text(encoding="utf-8"))
    help_text = (JS / "help.js").read_text(encoding="utf-8")
    block = help_text[help_text.index("const STAFF"):help_text.index("const titles")]
    found += [value for value in STRING.findall(block) if " " in value]
    found += KINDS.findall((JS / "mydata.js").read_text(encoding="utf-8"))
    found += list(FAILURE_TEXT.values())
    found += ["Please sign in again", "This server's rules changed, so Discord needs to confirm your account again."]  # sent by the server
    unique = list(dict.fromkeys(value for value in found if " " in value or value in SINGLE_WORDS))
    target = ROOT / "altwarden" / "web" / "static" / "i18n" / "en.json"
    target.write_text(json.dumps(unique, ensure_ascii=False, indent=0), encoding="utf-8")
    print(len(unique), "strings,", sum(map(len, unique)), "characters")


if __name__ == "__main__":
    main()

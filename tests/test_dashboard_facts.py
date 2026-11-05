"""The dashboard's facts that a browser isn't needed for. `scripts/browser_check.py --dash` runs its behavior in a real one."""
import json
import re
import sys
import unittest
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from test_flow import Base

from altwarden import altmatch, catalog

STATIC = ROOT / "altwarden" / "web" / "static"
DASH = sorted((STATIC / "dash").glob("*.js"))
SHEETS = [STATIC / "css" / "dashboard.css", STATIC / "css" / "base.css", STATIC / "css" / "site.css"]
OWN_FILES = [*DASH, STATIC / "dashboard.html", STATIC / "css" / "dashboard.css"]


def source(name: str) -> str:
    return (STATIC / "dash" / name).read_text(encoding="utf-8")


class CatalogTables(Base):
    async def test_the_catalog_carries_each_presets_whole_table(self):
        data = await (await self.client.get("/api/catalog")).json()
        self.assertEqual(data["presets"], json.loads(json.dumps(catalog.PRESETS)))

    async def test_a_preset_still_has_the_words_the_page_shows(self):
        data = await (await self.client.get("/api/catalog")).json()
        for name, table in catalog.PRESETS.items():
            self.assertEqual(data["presets"][name]["label"], table["label"])
            self.assertEqual(data["presets"][name]["blurb"], table["blurb"])


class RulesPageTables(unittest.TestCase):
    def test_the_evidence_table_matches_the_scores(self):
        block = re.search(r"const EVIDENCE_REACH = \{(.*?)\};", source("settings.js"), re.DOTALL).group(1)
        table = {key.strip('"'): value for key, value in re.findall(r'("[^"]*"|\w+): "(\w+)"', block)}
        methods = ("cookie", "fingerprint", "ip")
        kinds_of = {method: {kind for kind, owner in altmatch.METHOD_FOR_KIND.items() if owner == method} for method in methods}
        for size in range(len(methods) + 1):
            for chosen in combinations(methods, size):
                kinds = set().union(*(kinds_of[method] for method in chosen))
                self.assertEqual(table["+".join(chosen)], altmatch.confidence_for(altmatch.score_for(kinds)), chosen)

    def test_every_honeypot_action_is_explained(self):
        block = re.search(r"const HONEYPOT_HELP = \{(.*?)\n\};", source("settings.js"), re.DOTALL).group(1)
        self.assertEqual(set(re.findall(r"^\s*(\w+): `", block, re.MULTILINE)), set(catalog.HONEYPOT_ACTIONS))

    def test_the_confidence_labels_say_what_each_level_is(self):
        text = source("settings.js")
        self.assertIn("Confirmed: the same browser, proven by its cookie", text)
        self.assertIn("Likely: the same browser setup, or the same kind of computer, on the same connection", text)
        self.assertIn("Possible: a shared connection or a matching browser setup", text)

    def test_setup_doesnt_say_checks_only_watch(self):
        text = source("setup.js")
        self.assertNotIn("only watch", text)
        self.assertIn("Your server starts on the Standard rules, which stop anyone who fails a check.", text)


class PageRules(unittest.TestCase):
    def test_server_text_never_becomes_markup(self):
        for path in DASH:
            self.assertIsNone(re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|srcdoc", path.read_text(encoding="utf-8")), path.name)

    def test_nothing_needs_an_inline_style_or_handler(self):
        for path in DASH:
            self.assertNotIn('style:', path.read_text(encoding="utf-8"), path.name)
        self.assertIsNone(re.search(r"<style|style=|\son[a-z]+=", (STATIC / "dashboard.html").read_text(encoding="utf-8")))

    def test_shipped_words_stay_plain(self):
        banned = re.compile(r"\b(delve|tapestry|pivotal|underscore|testament|intricate|meticulous|garner|boasts|bolstered|enduring|vibrant|foster|showcase|highlight|emphasize|enhance|"
                            r"resonate|landscape|ecosystem|crucial|vital|essential|valuable|comprehensive|leverage|robust|seamless|powerful|modern|elevate|navigate|journey|streamline|empower|"
                            r"groundbreaking|renowned|nestled|profound|Authenticate" r"Me|colour|grey|behaviour|cancelled)\b", re.IGNORECASE)
        for path in OWN_FILES:
            words = banned.findall(re.sub(r"\bnavigate\(", "(", path.read_text(encoding="utf-8")))
            self.assertEqual(words, [], path.name)

    def test_no_invisible_characters_or_emoji_glyphs(self):
        carriers = re.compile("[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufe00-\ufe0f\ufeff\u2014]")
        for path in [*OWN_FILES, *SHEETS]:
            self.assertIsNone(carriers.search(path.read_text(encoding="utf-8")), path.name)
        sheet = (STATIC / "css" / "dashboard.css").read_text(encoding="utf-8")
        self.assertNotIn("\\1F512", sheet)
        self.assertNotIn("\\FE0E", sheet)


if __name__ == "__main__":
    unittest.main()

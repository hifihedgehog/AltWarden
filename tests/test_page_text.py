"""What the public pages and member pages say, held against the code, so a changed value can't leave a sentence behind."""
import json
import os
import re
import sys
import time
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from altwarden import altmatch, catalog, db as db_module, netintel, service as service_module, settings
from altwarden.bot import client as client_module
from altwarden.web import app as app_module
from fakes import GUILD, OLD_USER
from test_flow import Base as FlowBase

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "altwarden" / "web" / "static"
I18N = STATIC / "i18n"
LANGUAGES = ("de", "es", "fr", "ja", "ko", "pt", "ru", "zh")
PAGES = ("index.html", "docs.html", "security.html", "privacy.html", "terms.html", "help.html", "appeal.html", "mydata.html", "verify.html")
FILES = [STATIC / page for page in PAGES] + [ROOT / name for name in ("README.md", "SECURITY.md", "THIRD_PARTY.md")]


class _Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def visible(name: str) -> str:
    """A page's words, with markup gone and spacing squeezed, the way a reader sees them."""
    parser = _Text()
    parser.feed(read(name))
    return " ".join("".join(parser.parts).split())


def rows(page: str) -> dict[str, list[str]]:
    """Each table row of a page by its first cell, as plain text."""
    found = {}
    for row in re.findall(r"<tr>(.*?)</tr>", read(page), re.DOTALL):
        cells = [" ".join(re.sub(r"<[^>]+>", "", cell).split()) for cell in re.findall(r"<t[dh]>(.*?)</t[dh]>", row, re.DOTALL)]
        if cells:
            found[cells[0]] = cells[1:]
    return found


class CookieTable(unittest.TestCase):
    def test_every_cookie_the_site_sets_is_on_the_privacy_page(self):
        names = {value for key, value in vars(app_module).items() if key.endswith("_COOKIE") and isinstance(value, str)}
        self.assertEqual(names, {"__Host-aw_device", "__Host-aw_flow", "__Host-aw_vflow", "__Host-aw_session", "__Host-aw_browser"})
        table = rows("privacy.html")
        for name in names:
            self.assertIn(name, table)

    def test_a_cookie_the_page_names_exists(self):
        names = {value for key, value in vars(app_module).items() if key.endswith("_COOKIE") and isinstance(value, str)}
        self.assertEqual(set(re.findall(r"__Host-[a-z_]+", read("privacy.html"))), names)

    def test_lifetimes_match_the_code(self):
        table = rows("privacy.html")
        minutes = app_module.FLOW_SECONDS // 60
        self.assertIn(f"{minutes} minutes", table[app_module.FLOW_COOKIE][1])
        self.assertIn(f"{minutes} minutes", table[app_module.VERIFY_FLOW_COOKIE][1])
        session = table[app_module.SESSION_COOKIE][1]
        self.assertIn(f"{app_module.DASHBOARD_SECONDS // 3600} hours for the dashboard", session)
        self.assertIn(f"{app_module.MEMBER_SECONDS // 60} minutes for members", session)
        self.assertIn("every sign-in", session)

    def test_the_device_cookie_says_the_ceiling_the_code_uses(self):
        source = Path(app_module.__file__).read_text(encoding="utf-8")
        ceiling = re.search(r"min\(days, (\d+)\) \* 86400", source).group(1)
        self.assertIn(f"up to {ceiling} days", rows("privacy.html")[app_module.DEVICE_COOKIE][1])
        self.assertIn("renewed at each check", rows("privacy.html")[app_module.DEVICE_COOKIE][1])


class CommandTable(unittest.TestCase):
    def table(self):
        return {name.lstrip("/"): cells for name, cells in rows("docs.html").items() if name.startswith("/")}

    def test_each_staff_command_names_the_permissions_it_needs(self):
        table = self.table()
        for name, needed in settings.COMMAND_DEFAULTS.items():
            words = " and ".join(catalog.PERMISSION_LABELS[permission] for permission in needed)
            self.assertEqual(table[name][1], words, name)

    def test_every_command_in_the_bot_is_in_the_docs_and_the_readme(self):
        source = Path(client_module.__file__).read_text(encoding="utf-8")
        commands = re.findall(r'tree\.command\(name="([a-z-]+)"', source)
        self.assertGreater(len(commands), 10)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        docs = visible("docs.html")
        for name in commands:
            self.assertIn(f"/{name}", docs)
            self.assertIn(f"`/{name}`", readme)
        for name in re.findall(r'context_menu\(name="([A-Za-z ]+)"', source):
            self.assertIn(name, docs)
            self.assertIn(name, readme)

    def test_a_command_the_docs_list_exists(self):
        source = Path(client_module.__file__).read_text(encoding="utf-8")
        commands = set(re.findall(r'tree\.command\(name="([a-z-]+)"', source))
        for row in self.table():
            for name in re.findall(r"[a-z-]+", row):
                self.assertIn(name, commands)

    def test_the_old_advice_to_allow_a_command_in_both_places_is_gone(self):
        for page in ("docs.html", "dash/permissions.js"):
            self.assertNotIn("both places", read(page))
        self.assertIn("That one allow is enough", visible("docs.html"))
        self.assertIn("also lets them run it", read("dash/permissions.js"))


class AltMatching(unittest.TestCase):
    def test_the_evidence_table_names_what_counts_alone(self):
        table = rows("docs.html")
        self.assertIn("A VPN address or a carrier's shared IPv4 address doesn't make a match alone", table["Same connection"][0])
        self.assertIn("On a phone, tablet or Chromebook, it doesn't make a match alone", table["Same browser fingerprint"][0])
        self.assertIn("signed cookie", table["Same browser cookie"][0])

    def test_the_default_acts_on_any_match(self):
        self.assertEqual(settings.defaults()["checks"]["alt_account"]["min_confidence"], "possible")
        self.assertEqual({entry[2]["min_confidence"] for entry in (preset["checks"]["alt_account"] for preset in catalog.PRESETS.values())}, {"possible"})
        self.assertIn("Your setting for which matches to act on starts at any match", visible("docs.html"))

    def test_the_cases_the_docs_name_score_what_they_say(self):
        docs = visible("docs.html")
        self.assertIn("A cookie match is confirmed, the same connection is likely, and a fingerprint alone is possible", docs)
        self.assertEqual(altmatch.confidence_for(altmatch.score_for({"cookie"})), "confirmed")
        self.assertEqual(altmatch.confidence_for(altmatch.score_for({"ip"})), "likely")
        self.assertEqual(altmatch.confidence_for(altmatch.score_for({"fingerprint"})), "possible")

    def test_the_chosen_action_applies_to_any_match(self):
        check = settings.apply_preset(settings.defaults(), "strict")["checks"]["alt_account"]
        self.assertEqual(altmatch.judge(check, False, True), ("ban", "kick"))
        self.assertEqual(altmatch.judge(check, True, True)[0], "ban")
        self.assertIn("Any one match makes the new account an alt of the earlier one, and the action you choose applies", visible("docs.html"))
        self.assertIn("Any one match on the connection, browser cookie or fingerprint makes a second account an alt", visible("index.html"))

class Presets(unittest.TestCase):
    def row(self, name):
        return rows("docs.html")[name][0]

    def test_each_preset_row_holds_its_blurb(self):
        for table in catalog.PRESETS.values():
            self.assertIn(table["blurb"], self.row(table["label"]))

    def test_standards_numbers_match_the_table(self):
        limit = catalog.PRESETS["standard"]["checks"]["max_attempts"]
        self.assertTrue(limit[0])
        self.assertIn(f"up to {limit[2]['attempts']} times", self.row("Standard"))
        self.assertEqual(limit[2]["reset_minutes"], 1440)
        self.assertIn("attempts come back after a day", self.row("Standard"))
        off = sorted(check for check, entry in catalog.PRESETS["standard"]["checks"].items() if not entry[0])
        self.assertEqual(off, ["avatar", "mobile_data"])
        self.assertIn("Profile picture and Mobile data stay off", self.row("Standard"))
        alt = catalog.PRESETS["standard"]["checks"]["alt_account"][2]
        self.assertEqual((alt["alt_action"], alt["banned_alt_action"]), (catalog.KICK, catalog.BAN))
        self.assertIn("Kicks fake browser identities and alt accounts", self.row("Standard"))
        self.assertIn("An alt of a banned account is banned", self.row("Standard"))

    def test_stricts_numbers_match_the_table(self):
        table = catalog.PRESETS["strict"]
        self.assertEqual(table["auto_kick_minutes"], 10)
        self.assertIn(f"within {table['auto_kick_minutes']} minutes", self.row("Strict"))
        self.assertIn(f"{table['checks']['account_age'][2]['days']} days old", self.row("Strict"))
        limit = table["checks"]["max_attempts"][2]
        self.assertEqual((limit["attempts"], limit["reset_minutes"]), (3, 0))
        self.assertIn("Three failed attempts end it for good", self.row("Strict"))
        alt = table["checks"]["alt_account"][2]
        self.assertEqual((alt["alt_action"], alt["main_action"]), (catalog.BAN, catalog.KICK))
        self.assertIn("are banned, and the earlier account is kicked", self.row("Strict"))
        denies = sorted(check for check, entry in table["checks"].items() if entry[1] == catalog.DENY)
        self.assertEqual(denies, ["devtools", "mobile_data", "privacy"])
        self.assertIn("Mobile data, Developer tools and Fingerprint blocking deny", self.row("Strict"))

    def test_gentle_removes_nobody_as_its_row_says(self):
        table = catalog.PRESETS["gentle"]["checks"]
        self.assertTrue(all(entry[1] == catalog.DENY for entry in table.values()))
        self.assertEqual(table["alt_account"][2]["banned_alt_action"], catalog.DENY)
        self.assertIn("nobody is removed", self.row("Gentle"))

    def test_the_new_server_default_is_the_preset_the_pages_call_the_default(self):
        self.assertEqual(catalog.DEFAULT_PRESET, "standard")
        self.assertIn("The default.", self.row("Standard"))
        self.assertIn("The Standard preset", (ROOT / "README.md").read_text(encoding="utf-8"))

    def test_no_preset_is_built_on_watch_as_the_home_page_says(self):
        for table in catalog.PRESETS.values():
            self.assertFalse([check for check, entry in table["checks"].items() if entry[1] == catalog.WATCH])
        text = visible("index.html")
        self.assertIn("Try a rule in Watch first", text)
        self.assertIn("no preset is built on Watch", text)


class Retention(unittest.TestCase):
    def limits(self, field):
        low = settings.normalize({"privacy": {field: -99999}})["privacy"][field]
        high = settings.normalize({"privacy": {field: 99999}})["privacy"][field]
        return settings.defaults()["privacy"][field], low, high

    def test_the_table_matches_the_settings(self):
        table = rows("privacy.html")
        for row, field in (("Connection hash", "ip_days"), ("Browser, device, system and cookie hashes", "identifier_days"),
                           ("Attempt history, staff audit log, appeals whether decided or not", "attempt_days"),
                           ("Browser, device, system and cookie hashes of banned accounts, and the record of the ban", "banned_days")):
            default, low, high = self.limits(field)
            self.assertEqual(table[row], [f"{default} days", f"{low} to {high:,} days"], row)

    def test_the_departure_window_matches_the_code(self):
        self.assertEqual(db_module.DEPARTED_DAYS, 30)
        self.assertIn(f"deleted after {db_module.DEPARTED_DAYS} days", visible("privacy.html"))
        self.assertIn("within 30 days", read("js/help.js"))

    def test_link_lifetimes_match_the_code(self):
        table = rows("privacy.html")["Verification links"]
        self.assertEqual(service_module.LINK_MINUTES, 60)
        self.assertIn("1 hour", table[0])
        self.assertIn(f"up to {service_module.MAX_BYPASS_HOURS // 24} days", table[1])
        self.assertIn(f"1 to {service_module.MAX_BYPASS_HOURS} hours", visible("docs.html"))

    def test_backups_are_stated_and_match_the_nightly_job(self):
        install = ROOT / "deploy" / "install.sh"
        if install.exists():  # the deploy folder stays out of the public repository
            self.assertIn("-mtime +12 -delete", install.read_text(encoding="utf-8"))
        self.assertEqual(rows("privacy.html")["Backup copies of the whole database"][0], "Up to 14 days")
        self.assertIn("Whatever is deleted can stay in a backup for up to 14 days", visible("privacy.html"))
        self.assertIn("up to 14 days", read("js/mydata.js"))

    def test_the_stored_secrets_sentences_say_they_are_sealed(self):
        self.assertEqual(db_module.SEALED_COLUMNS, (("lookup_keys", "guild_id", "lookup_key"), ("webhooks", "id", "secret"), ("webhooks", "id", "url")))
        security = visible("security.html")
        self.assertNotIn("stored readable", security)
        self.assertIn("A stolen database alone reveals none of them", security)
        privacy = visible("privacy.html")
        self.assertNotIn("alone reveals nothing", privacy)
        self.assertIn("a copy alone reveals none of them", privacy)
        self.assertIn("so a copy of it shows no Discord IDs, names, attempt results or appeal text", privacy)
        self.assertIn("An encrypted file. The database, its write-ahead log and its nightly backups are encrypted with SQLCipher", security)


class Limits(unittest.TestCase):
    def test_the_lookup_numbers_match_the_code(self):
        docs = visible("docs.html")
        self.assertEqual(service_module.LOOKUP_CACHE_SECONDS, 3600)
        self.assertIn("kept for an hour per network", docs)
        self.assertIn(f"at most {service_module.LOOKUP_DAILY_LIMIT} lookups a day", docs)
        self.assertEqual(service_module.LOOKUP_WARNING_SECONDS, 86400)
        self.assertIn("told once a day", docs)

    def test_the_lists_refresh_as_often_as_the_page_says(self):
        self.assertEqual(netintel.REFRESH_SECONDS, 7 * 86400)

    def test_the_rule_ranges_match_the_settings(self):
        docs = visible("docs.html")
        reset = settings.normalize({"checks": {"max_attempts": {"reset_minutes": 1}}})["checks"]["max_attempts"]["reset_minutes"]
        self.assertEqual(reset, settings.MIN_RESET_MINUTES)
        self.assertEqual(settings.normalize({"checks": {"max_attempts": {"reset_minutes": 99999}}})["checks"]["max_attempts"]["reset_minutes"], 43200)
        self.assertIn(f"after {settings.MIN_RESET_MINUTES} minutes to 30 days, or never", docs)
        self.assertEqual(settings.normalize({"core": {"auto_kick": {"minutes": 99999}}})["core"]["auto_kick"]["minutes"], 10080)
        self.assertEqual(settings.normalize({"core": {"auto_kick": {"minutes": 1}}})["core"]["auto_kick"]["minutes"], 5)
        self.assertIn("from 5 minutes to 7 days", docs)
        self.assertEqual(settings.normalize({"checks": {"account_age": {"days": 99999}}})["checks"]["account_age"]["days"], 3650)
        self.assertIn("up to 10 years", docs)

    def test_the_appeal_window_matches_the_code(self):
        self.assertEqual(service_module.APPEAL_WINDOW, 7 * 86400)
        self.assertIn("for 7 days after a failed attempt", visible("docs.html"))

    def test_counts_of_fonts_effects_and_pictures_match_the_code(self):
        docs = visible("docs.html")
        self.assertIn("one of eight pictures", docs)
        self.assertEqual(len(settings.AVATAR_COLORS), 8)
        self.assertIn(f"any of {len(settings.NAME_FONTS)} fonts and {len(settings.NAME_EFFECTS)} effects", docs)

    def test_webhook_events_match_the_code(self):
        from altwarden.web import api
        docs = visible("docs.html")
        for event in api.WEBHOOK_EVENTS:
            self.assertIn(event, docs)
        self.assertEqual(set(re.findall(r"\b(?:member|appeal|raid)\.[a-z]+", docs)), set(api.WEBHOOK_EVENTS))

    def test_the_rooted_check_says_pixels_in_all_three_places(self):
        self.assertIn("Pixel", catalog.BY_ID["rooted"].blurb)
        self.assertIn("Pixel", (ROOT / "README.md").read_text(encoding="utf-8"))

    def test_the_developer_tools_text_says_safari_and_phones(self):
        self.assertIn("Not available on Safari or phones", rows("docs.html")["Developer tools"][0])

    def test_every_page_navigation_has_a_name(self):
        for page in ("index.html", "docs.html"):
            for tag in re.findall(r"<nav\b[^>]*>", read(page)):
                self.assertIn("aria-label=", tag, page)

    def test_nothing_offers_to_add_the_bot(self):
        for page in ("index.html", "docs.html", "security.html", "privacy.html", "terms.html"):
            self.assertNotRegex(visible(page).lower(), r"(add|invite) (altwarden|the bot) to your server(?! with the link)")
        self.assertIn("This copy runs only on its owner's servers", visible("docs.html"))


class ThirdParty(unittest.TestCase):
    TEXT = (ROOT / "THIRD_PARTY.md").read_text(encoding="utf-8")

    def test_every_vendored_file_is_named(self):
        for path in (STATIC / "vendor").iterdir():
            if path.is_file():
                self.assertIn(f"`altwarden/web/static/vendor/{path.name}`", self.TEXT)

    def test_a_vendored_file_it_names_exists(self):
        for name in re.findall(r"`(altwarden/web/static/[^`]+\.(?:js|json))`", self.TEXT):
            self.assertTrue((ROOT / name).is_file(), name)

    def test_each_library_file_is_the_project_its_row_names(self):
        for project, version, name in (("FingerprintJS", "5.3.0", "a-5.3.0.min.js"), ("BotD", "2.0.0", "b-2.0.0.esm.js"), ("detectIncognito", "1.9.0", "c-1.9.0.min.js")):
            row = next(line for line in self.TEXT.splitlines() if name in line)
            self.assertIn(f"[{project}]", row)
            self.assertIn(f"| {version} |", row)
            self.assertIn(f"{project} v{version}", (STATIC / "vendor" / name).read_text(encoding="utf-8")[:300])

    def test_every_locked_package_is_listed_with_its_version(self):
        locked = re.findall(r"^([a-zA-Z0-9_.-]+)==([0-9][^\s\\]*)", (ROOT / "requirements.lock").read_text(encoding="utf-8"), re.MULTILINE)
        self.assertGreater(len(locked), 10)
        for name, version in locked:
            shown = "discord.py" if name == "discord-py" else name
            self.assertRegex(self.TEXT, rf"\[{re.escape(shown)}\]\([^)]+\) \| {re.escape(version)} \|", name)

    def test_every_list_downloaded_at_runtime_is_listed(self):
        for name, url in netintel.SOURCES.items():
            project = {"github.com/sapics": "sapics/ip-location-db", "raw.githubusercontent.com/X4BNet": "X4BNet/lists_vpn",
                       "raw.githubusercontent.com/Joe12387": "Joe12387/open-source-vpn-ip-lists",
                       "raw.githubusercontent.com/disposable-email-domains": "disposable-email-domains/disposable-email-domains",
                       "check.torproject.org": "check.torproject.org/torbulkexitlist", "mask-api.icloud.com": "mask-api.icloud.com/egress-ip-ranges.csv"}
            found = next((text for start, text in project.items() if url.split("//")[1].startswith(start)), None)
            self.assertIsNotNone(found, url)
            self.assertIn(found, self.TEXT)

    def test_the_country_file_is_pinned_and_its_changes_stated(self):
        row = next(line for line in self.TEXT.splitlines() if "countries.json" in line)
        self.assertRegex(row, r"commit [0-9a-f]{7}")
        self.assertIn("cut down to five fields", row)
        self.assertNotIn("master", row)
        self.assertEqual(set(json.loads(read("countries.json"))[0]), {"code", "num", "name", "continent", "region"})

    def test_the_upstream_license_of_the_vpn_list_is_stated(self):
        row = next(line for line in self.TEXT.splitlines() if "X4BNet" in line)
        self.assertIn("CC BY-SA 4.0", row)


class Translations(unittest.TestCase):
    def english(self):
        return json.loads((I18N / "en.json").read_text(encoding="utf-8"))

    def test_the_committed_list_is_what_the_script_builds(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import extract_strings
        written = {}

        def capture(path, text, **_):
            written[path.name] = text
        with patch.object(Path, "write_text", capture), patch("builtins.print"):
            extract_strings.main()
        self.assertEqual(json.loads(written["en.json"]), self.english())

    def test_every_language_holds_every_string_with_its_placeholders(self):
        english = self.english()
        for code in LANGUAGES:
            strings = json.loads((I18N / f"{code}.json").read_text(encoding="utf-8"))
            self.assertEqual(list(strings), english, code)
            for key, value in strings.items():
                self.assertTrue(value.strip(), (code, key))
                self.assertEqual(sorted(re.findall(r"\{\w+\}", key)), sorted(re.findall(r"\{\w+\}", value)), (code, key))

    def test_nothing_is_left_in_english(self):
        # A word the two languages share is the only exception.
        allowed = {("de", "Status"), ("pt", "Status")}
        for code in LANGUAGES:
            strings = json.loads((I18N / f"{code}.json").read_text(encoding="utf-8"))
            same = {(code, key) for key, value in strings.items() if key == value} - allowed
            self.assertEqual(same, set())

    def test_why_an_appeal_is_refused_reaches_the_list(self):
        english = set(self.english())
        source = Path(service_module.__file__).read_text(encoding="utf-8")
        block = source[source.index("async def submit_appeal"):source.index("async def appeal_state")]
        refusals = re.findall(r'(?:return|return last,|else) "([^"]+)"', block)
        self.assertEqual(len(set(refusals)), 8)
        self.assertLessEqual(set(refusals), english)

    def test_every_string_a_member_page_asks_for_is_listed(self):
        english = set(self.english())
        for name in ("help.js", "appeal.js", "mydata.js", "verify.js"):
            source = read(f"js/{name}")
            for text in re.findall(r'\b(?:t|line)\("((?:[^"\\]|\\.)*)"', source):
                self.assertIn(text, english, name)

    def test_the_singular_of_tries_left_is_in_every_language(self):
        self.assertIn('left === 1 ? t("1 try left.")', read("js/verify.js"))
        for code in LANGUAGES:
            self.assertIn("1 try left.", json.loads((I18N / f"{code}.json").read_text(encoding="utf-8")))

    def test_every_help_slug_the_server_sends_has_a_page(self):
        source = read("js/help.js")
        for slug in catalog.HELP_SLUG.values():
            self.assertTrue(f'"{slug}":' in source or f"\n  {slug}:" in source, slug)


class WhatThePagesRead(FlowBase):
    """The pages read fields by name, so a renamed key would leave a blank with nothing failing."""

    async def seed(self):
        await self.db.touch_member(GUILD, OLD_USER, username="sam", avatar="abc")
        await self.db.mark_verified(GUILD, OLD_USER, "web")
        await self.db.add_attempt(GUILD, OLD_USER, "failed", check_id="vpn", action="deny", mode="web")
        await self.db.store_identifier(GUILD, OLD_USER, "ip", "a" * 32, time.time() + 60)

    async def test_every_field_my_data_reads_comes_from_the_service(self):
        await self.seed()
        record = (await self.service.my_data(OLD_USER))[0]
        source = read("js/mydata.js")
        for field in set(re.findall(r"\bentry\.(\w+)", source)):
            self.assertIn(field, record, field)
        for field in set(re.findall(r"\bkind\.(\w+)", source)):
            self.assertIn(field, record["stored_hashes"][0], field)

    async def test_my_data_status_words_cover_what_the_service_stores(self):
        source = read("js/mydata.js")
        words = set(re.findall(r'\["(\w+)", t\("', source))
        code = Path(service_module.__file__).read_text(encoding="utf-8") + Path(db_module.__file__).read_text(encoding="utf-8")
        stored = set(re.findall(r"status = '(\w+)'", code)) & {"pending", "verified", "approved", "failed"} | set(re.findall(r'status="(\w+)"', code))
        self.assertEqual(stored, words)

    async def test_every_field_the_appeal_page_reads_comes_from_the_route(self):
        await self.seed()
        source = read("js/appeal.js")
        state = await self.service.appeal_state(GUILD, OLD_USER)
        fields = set(re.findall(r"\bdata\.(\w+)", source))
        route = Path(app_module.__file__).read_text(encoding="utf-8")
        body = route[route.index("async def me_appeal_state"):route.index("async def me_appeal(")]
        for field in fields:
            self.assertIn(f'"{field}":', body, field)
        self.assertIn("latest", state)
        service_code = Path(service_module.__file__).read_text(encoding="utf-8")
        query = service_code[service_code.index("async def appeal_state"):service_code.index("async def decide_appeal")]
        for field in set(re.findall(r"\blatest\.(\w+)", source)):
            self.assertRegex(query, rf"SELECT[^\"]*\b{field}\b", field)


class PublicProse(unittest.TestCase):
    # By code point, so this file stays plain ASCII and passes its own sweep.
    INVISIBLE = {chr(code) for code in (0xAD, 0xA0, 0x34F, 0x61C, 0x115F, 0x1160, 0x17B4, 0x17B5, *range(0x180B, 0x1810), *range(0x2000, 0x2010), *range(0x202A, 0x2030),
                                        0x205F, *range(0x2060, 0x2070), 0x3000, 0x3164, *range(0xFE00, 0xFE10), 0xFEFF, 0xFFA0, *range(0xFFF9, 0xFFFC))}
    BANNED = re.compile(r"\b(delve|tapestry|pivotal|underscore|testament|intricate|meticulous|garner|boasts|bolstered|enduring|vibrant|foster|showcase|highlight|emphasize|enhance|resonate|landscape|ecosystem|crucial|vital|essential|valuable|comprehensive|leverage|robust|seamless|powerful|modern|elevate|navigate|journey|streamline|empower|groundbreaking|renowned|nestled|profound|not just|not only)\b", re.IGNORECASE)
    BRITISH = re.compile(r"colour|\bgrey\b|centre|neighbour|behaviour|modelled|labelled|cancelled|travelling|normalise|initialise|recognise|analyse\b|defence|offence|licence|towards|afterwards|learnt|spelt\b|whilst|amongst|\bmaths\b|favour|honour", re.IGNORECASE)
    NAMES = re.compile(r"authenticate" r"me|\bclaude\b|\bcodex\b|\bgpt\b|\bcopilot\b|\bgemini\b|\bopus\b|\bsonnet\b|\bastra\b|subagent|ai[- ]review|ai[- ]translated", re.IGNORECASE)

    def texts(self):
        for path in FILES:
            yield path.name, path.read_text(encoding="utf-8")
        english = json.loads((I18N / "en.json").read_text(encoding="utf-8"))
        yield "en.json", "\n".join(english)
        for code in LANGUAGES:
            yield f"{code}.json", (I18N / f"{code}.json").read_text(encoding="utf-8")

    def test_no_invisible_characters(self):
        for name, text in self.texts():
            self.assertEqual(sorted(hex(ord(character)) for character in set(text) & self.INVISIBLE), [], name)

    def test_no_listed_word_british_spelling_or_tool_name_in_english(self):
        english = [(name, text) for name, text in self.texts() if name not in {f"{code}.json" for code in LANGUAGES}]
        for name, text in english:
            for pattern in (self.BANNED, self.BRITISH, self.NAMES):
                self.assertIsNone(pattern.search(text), f"{name}: {pattern.search(text)}")

    def test_no_em_dash_in_any_encoding(self):
        for name, text in self.texts():
            self.assertNotRegex(text, chr(0x2014) + "|&mdash;|&#8212;|&#x2014;|" + chr(92) * 2 + "u2014", name)


if __name__ == "__main__":
    unittest.main()

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from altwarden import altmatch, catalog, db, engine, netintel, settings, signals
from altwarden.netintel import NetInfo, external_lookup

CHROME_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
FIREFOX_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0"
SAFARI_IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
CHROME_ANDROID = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"
ANGLE_NVIDIA = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)"


def clean_report(**changes):
    report = {
        "v": 1,
        "fp": {"id": "a" * 32, "confidence": 0.9},
        "private": {"isPrivate": False, "browser": "Chrome"},
        "bot": {"bot": False},
        "nav": {"ua": CHROME_WIN, "platform": "Win32", "vendor": "Google Inc.", "webdriver": False, "cores": 16, "memory": 8},
        "uad": {"brands": [], "mobile": False, "platform": "Windows"},
        "scr": {"w": 2560, "h": 1440, "iw": 2560, "ih": 1300, "ow": 2560, "oh": 1400},
        "tz": {"name": "America/Chicago", "offset": 360, "intlOffset": 360},
        "gpu": {"vendor": "Google Inc. (NVIDIA)", "renderer": ANGLE_NVIDIA},
        "worker": {"ua": CHROME_WIN, "platform": "Win32", "cores": 16, "memory": 8, "tz": "America/Chicago", "gpu": ANGLE_NVIDIA},
        "eng": {"evalLen": 33},
        "lies": {"total": 0, "apis": []},
        "canvas": {"noisy": False, "blocked": False},
        "privacy": {},
        "devtools": {"timing": False},
        "act": {"pointer": 12, "ms": 2500, "visible": True},
    }
    report.update(changes)
    return report


def judge(report=None, ua=CHROME_WIN, headers=None):
    head = {"User-Agent": ua}
    head.update(headers or {})
    return signals.evaluate(report if report is not None else clean_report(), head)


class CleanBrowsers(unittest.TestCase):
    def assert_clean(self, verdict):
        for name in ("automated", "antidetect", "fake_ua", "devtools", "private", "privacy", "vm", "emulated"):
            self.assertFalse(getattr(verdict, name), (name, verdict.reasons))
        self.assertEqual(verdict.tamper_score, 0)
        self.assertLess(verdict.bot_score, 50)

    def test_windows_chrome(self):
        self.assert_clean(judge())

    def test_mac_firefox(self):
        report = clean_report(nav={"ua": FIREFOX_MAC, "platform": "MacIntel", "vendor": "", "webdriver": False, "cores": 8},
                              uad={}, gpu={"renderer": "Apple M1, or similar"}, eng={"evalLen": 37},
                              worker={"ua": FIREFOX_MAC, "platform": "MacIntel", "cores": 8, "tz": "America/Chicago"})
        self.assert_clean(judge(report, FIREFOX_MAC))

    def test_iphone_safari(self):
        report = clean_report(nav={"ua": SAFARI_IPHONE, "platform": "iPhone", "vendor": "Apple Computer, Inc.", "cores": 6},
                              uad={}, gpu={"renderer": "Apple GPU"}, eng={"evalLen": 37}, worker={})
        verdict = judge(report, SAFARI_IPHONE)
        self.assert_clean(verdict)
        self.assertTrue(verdict.weak_fingerprint)

    def test_phone_requesting_desktop_site_is_not_a_fake(self):
        desktop_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        report = clean_report(nav={"ua": desktop_agent, "platform": "Linux armv81", "vendor": "Google Inc.", "cores": 8},
                              uad={"mobile": False, "platform": "Android"},
                              gpu={"renderer": "Adreno (TM) 740"}, worker={})
        self.assertFalse(judge(report, desktop_agent).fake_ua)

    def test_ipad_reporting_mac_is_not_a_fake(self):
        agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"
        report = clean_report(nav={"ua": agent, "platform": "MacIntel", "vendor": "Apple Computer, Inc.", "cores": 8},
                              uad={}, gpu={"renderer": "Apple GPU"}, eng={"evalLen": 37}, worker={})
        self.assertFalse(judge(report, agent).fake_ua)


class Hostile(unittest.TestCase):
    def test_botd_verdict(self):
        verdict = judge(clean_report(bot={"bot": True, "botKind": "selenium"}))
        self.assertTrue(verdict.automated)
        self.assertEqual(verdict.bot_score, 100)
        self.assertIn("BotD: selenium", verdict.reasons["automated"])

    def test_webdriver_flag(self):
        report = clean_report()
        report["nav"]["webdriver"] = True
        self.assertTrue(judge(report).automated)

    def test_headless_only_visible_in_worker(self):
        report = clean_report()
        report["worker"]["ua"] = CHROME_WIN.replace("Chrome/", "HeadlessChrome/")
        verdict = judge(report)
        self.assertTrue(verdict.automated)
        self.assertTrue(verdict.fake_ua)

    def test_request_and_page_disagree(self):
        self.assertTrue(judge(clean_report(), FIREFOX_MAC).fake_ua)

    def test_wrong_engine_for_the_agent(self):
        self.assertTrue(judge(clean_report(eng={"evalLen": 37})).fake_ua)

    def test_windows_agent_with_apple_graphics(self):
        report = clean_report(gpu={"renderer": "ANGLE (Apple, Apple M2, OpenGL 4.1)"})
        report["worker"] = {}
        self.assertTrue(judge(report).fake_ua)

    def test_client_hints_name_another_system(self):
        self.assertTrue(judge(headers={"Sec-CH-UA-Platform": '"macOS"'}).fake_ua)

    def test_worker_sees_other_hardware(self):
        report = clean_report()
        report["worker"]["cores"] = 4
        self.assertTrue(judge(report).antidetect)

    def test_worker_sees_other_time_zone(self):
        report = clean_report()
        report["worker"]["tz"] = "Europe/Paris"
        self.assertTrue(judge(report).antidetect)

    def test_rewritten_device_functions(self):
        verdict = judge(clean_report(lies={"total": 2, "apis": ["Navigator.hardwareConcurrency", "Screen.width"]}))
        self.assertTrue(verdict.antidetect)
        self.assertEqual(verdict.tamper_score, 20)

    def test_canvas_noise_without_a_privacy_browser(self):
        self.assertTrue(judge(clean_report(canvas={"noisy": True})).antidetect)

    def test_canvas_noise_on_brave_is_privacy_not_antidetect(self):
        verdict = judge(clean_report(canvas={"noisy": True}, privacy={"brave": True}))
        self.assertFalse(verdict.antidetect)
        self.assertTrue(verdict.privacy)

    def test_clock_and_zone_disagree(self):
        self.assertTrue(judge(clean_report(tz={"name": "America/Chicago", "offset": 360, "intlOffset": 0})).antidetect)

    def test_tamper_score_counts_toString_and_proxies(self):
        verdict = judge(clean_report(lies={"total": 1, "apis": ["Foo.bar"], "toString": True, "proxy": True}))
        self.assertEqual(verdict.tamper_score, 80)

    def test_private_window(self):
        self.assertTrue(judge(clean_report(private={"isPrivate": True})).private)

    def test_virtual_machine_graphics(self):
        for renderer in ("VMware SVGA 3D", "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)",
                         "llvmpipe (LLVM 15.0.7, 256 bits)", "Parallels Display Adapter (WDDM)", "VirtualBox Graphics Adapter",
                         "Microsoft Basic Render Driver"):
            report = clean_report(gpu={"renderer": renderer})
            report["worker"] = {}
            self.assertTrue(judge(report).vm, renderer)

    def test_developer_tools(self):
        self.assertTrue(judge(clean_report(devtools={"timing": True})).devtools)


    def other_engine(self, agent, platform, vendor, tools):
        return judge(clean_report(nav={"ua": agent, "platform": platform, "vendor": vendor, "webdriver": False, "cores": 8}, uad={}, gpu={"renderer": ""},
                                  eng={"evalLen": 37}, worker={}, devtools=tools), agent)

    def test_console_timing_is_not_trusted_on_safari(self):
        safari = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
        self.assertFalse(self.other_engine(safari, "MacIntel", "Apple Computer, Inc.", {"timing": True}).devtools)
        self.assertTrue(self.other_engine(FIREFOX_MAC, "MacIntel", "", {"timing": True}).devtools)

    def test_window_gap_on_a_phone_is_not_devtools(self):
        report = clean_report(nav={"ua": CHROME_ANDROID, "platform": "Linux armv81", "vendor": "Google Inc.", "cores": 8},
                              uad={"mobile": True, "platform": "Android"}, gpu={"renderer": "Adreno (TM) 740"},
                              devtools={"size": True}, worker={})
        self.assertFalse(judge(report, CHROME_ANDROID).devtools)

    def test_android_emulator(self):
        for uad, renderer, platform in (({"mobile": True, "model": "sdk_gphone64_x86_64", "platform": "Android"}, "Adreno", "Linux armv81"),
                                        ({"mobile": True, "platform": "Android"}, "NVIDIA GeForce RTX 3080", "Linux armv81"),
                                        ({"mobile": True, "platform": "Android"}, "Mali-G710", "Linux x86_64")):
            report = clean_report(nav={"ua": CHROME_ANDROID, "platform": platform, "vendor": "Google Inc.", "cores": 8},
                                  uad=uad, gpu={"renderer": renderer}, worker={})
            self.assertTrue(judge(report, CHROME_ANDROID).emulated, (uad, renderer, platform))

    def phone(self, model, renderer, version=None):
        uad = {"mobile": True, "platform": "Android", "model": model}
        if version:
            uad["platformVersion"] = version
        report = clean_report(nav={"ua": CHROME_ANDROID, "platform": "Linux armv81", "vendor": "Google Inc.", "cores": 8}, uad=uad, gpu={"renderer": renderer}, worker={})
        return judge(report, CHROME_ANDROID)

    def test_a_model_that_doesnt_fit_its_graphics_chip(self):
        for model, renderer in (("Pixel 9 Pro", "Adreno (TM) 750"), ("Pixel 7", "Adreno (TM) 730"), ("Pixel Fold", "Adreno (TM) 730"),
                                ("Pixel 3", "Mali-G78"), ("Pixel XL", "PowerVR GE8320")):
            verdict = self.phone(model, renderer)
            self.assertTrue(verdict.emulated, model)
            self.assertIn("phone model doesn't fit its graphics chip", verdict.reasons["emulated"])

    def test_real_pixels_pass(self):
        for model, renderer, version in (("Pixel 3", "Adreno (TM) 630", "12.0.0"), ("Pixel 5", "Adreno (TM) 620", "14.0.0"), ("Pixel 6", "Mali-G78", "16.0.0"),
                                         ("Pixel 9", "Mali-G715", "16.0.0"), ("Pixel 10", "PowerVR D-Series DXT-48-1536", "16.0.0"), ("Pixel 4a (5G)", "Adreno (TM) 620", "14.0.0")):
            self.assertFalse(self.phone(model, renderer, version).emulated, model)

    def test_android_newer_than_the_phone_ever_got(self):
        for model, renderer, version in (("Pixel", "Adreno (TM) 530", "11.0.0"), ("Pixel 3", "Adreno (TM) 630", "14.0.0"), ("Pixel 4a", "Adreno (TM) 618", "15.0.0"), ("Pixel 5", "Adreno (TM) 620", "15"),):
            verdict = self.phone(model, renderer, version)
            self.assertTrue(verdict.emulated, model)
            self.assertIn("Android newer than this phone ever shipped with", verdict.reasons["emulated"])

    def test_other_phones_and_missing_values_flag_nothing(self):
        for model, renderer, version in (("SM-S918U", "Adreno (TM) 740", "16.0.0"), ("SM-G991B", "Mali-G78", "15.0.0"), ("Pixel 3", "", None), ("", "Adreno (TM) 630", "14.0.0"), ("Pixel 3", "Adreno (TM) 630", "unknown")):
            self.assertFalse(self.phone(model, renderer, version).emulated, (model, version))

    def test_a_chromebook_is_not_a_fake(self):
        agent = "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        report = clean_report(nav={"ua": agent, "platform": "Linux x86_64", "vendor": "Google Inc.", "cores": 8},
                              uad={"mobile": False, "platform": "Chrome OS"}, gpu={"renderer": "ANGLE (Intel, Mesa Intel(R) UHD Graphics)"}, worker={})
        self.assertFalse(judge(report, agent).fake_ua, judge(report, agent).reasons)

    def test_firefox_on_iphone_is_not_a_fake(self):
        agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/130.0 Mobile/15E148 Safari/605.1.15"
        report = clean_report(nav={"ua": agent, "platform": "iPhone", "vendor": "Apple Computer, Inc.", "cores": 6}, uad={},
                              gpu={"renderer": "Apple GPU"}, eng={"evalLen": 37}, worker={})
        self.assertFalse(judge(report, agent).fake_ua, judge(report, agent).reasons)

    def test_other_ios_browsers_are_not_fakes(self):
        for token in ("CriOS/130.0.0.0", "EdgiOS/130.0.0.0", "OPT/5.0.0"):
            agent = f"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) {token} Mobile/15E148 Safari/604.1"
            report = clean_report(nav={"ua": agent, "platform": "iPhone", "vendor": "Apple Computer, Inc.", "cores": 6}, uad={},
                                  gpu={"renderer": "Apple GPU"}, eng={"evalLen": 37}, worker={})
            self.assertFalse(judge(report, agent).fake_ua, token)

    def test_firefox_on_android_and_linux_are_not_fakes(self):
        for agent, platform in (("Mozilla/5.0 (Android 14; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0", "Linux aarch64"),
                                ("Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0", "Linux x86_64")):
            report = clean_report(nav={"ua": agent, "platform": platform, "vendor": "", "cores": 8}, uad={}, gpu={"renderer": "Mali-G78"}, eng={"evalLen": 37}, worker={})
            self.assertFalse(judge(report, agent).fake_ua, agent)

    def test_linux_on_apple_hardware_is_not_a_fake(self):
        agent = "Mozilla/5.0 (X11; Linux aarch64; rv:130.0) Gecko/20100101 Firefox/130.0"
        report = clean_report(nav={"ua": agent, "platform": "Linux aarch64", "vendor": "", "cores": 8}, uad={},
                              gpu={"renderer": "Apple M1 (G13G B1)"}, eng={"evalLen": 37}, worker={})
        self.assertFalse(judge(report, agent).fake_ua)

    def test_a_shield_tv_is_not_an_emulator(self):
        self.assertFalse(self.phone("SHIELD Android TV", "NVIDIA Tegra").emulated)
        self.assertTrue(self.phone("SM-S918U", "NVIDIA GeForce RTX 3080").emulated)

    def test_randomized_canvas_means_different_things_by_engine(self):
        for agent, vendor, length, private in (("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0", "", 37, True),
                                               ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15", "Apple Computer, Inc.", 37, False)):
            platform = "Win32" if "Windows" in agent else "MacIntel"
            verdict = judge(clean_report(nav={"ua": agent, "platform": platform, "vendor": vendor, "cores": 8}, uad={}, gpu={"renderer": ""},
                                         eng={"evalLen": length}, canvas={"noisy": True, "blocked": False}, worker={}), agent)
            self.assertEqual(verdict.privacy, private, agent)
            self.assertFalse(verdict.antidetect, agent)

    def test_real_phone_is_not_an_emulator(self):
        report = clean_report(nav={"ua": CHROME_ANDROID, "platform": "Linux armv81", "vendor": "Google Inc.", "cores": 8},
                              uad={"mobile": True, "platform": "Android", "model": "Pixel 8"},
                              gpu={"renderer": "Mali-G715"}, worker={})
        self.assertFalse(judge(report, CHROME_ANDROID).emulated)


class Robustness(unittest.TestCase):
    def test_junk_reports_never_crash(self):
        for junk in (None, [], "x", 5, {"nav": 5, "bot": "yes", "lies": {"apis": "no", "total": "many"}, "gpu": [], "scr": None},
                     {"worker": {"cores": {}}, "tz": {"offset": "x"}, "fp": {"id": 5}, "act": {"ms": "a"}}):
            signals.evaluate(junk, {})

    def test_bad_fingerprint_is_ignored(self):
        self.assertIsNone(judge(clean_report(fp={"id": "'; drop table"})).fingerprint)

    def test_device_value_survives_browser_wrappers(self):
        chrome = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)"
        firefox = "NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11"
        self.assertEqual(signals.gpu_model(chrome), signals.gpu_model(firefox))

    def test_device_value_is_stable_across_browsers(self):
        one = judge()
        report = clean_report(nav={"ua": CHROME_WIN, "platform": "Win32", "vendor": "Google Inc.", "cores": 16},
                              fp={"id": "b" * 32})
        self.assertEqual(one.device, judge(report).device)
        self.assertNotEqual(one.fingerprint, judge(report).fingerprint)


class SuspectScore(unittest.TestCase):
    def test_adds_up_and_caps(self):
        verdict = signals.BrowserVerdict(automated=True, antidetect=True)
        score, hits = signals.suspect_score(verdict, NetInfo(vpn=True), account_days=1, has_avatar=False,
                                            disposable=True, timezone_mismatch=True)
        self.assertEqual(score, 100)
        self.assertIn("vpn", hits)

    def test_clean_member_scores_zero(self):
        score, hits = signals.suspect_score(signals.BrowserVerdict(), NetInfo(), account_days=900, has_avatar=True,
                                            disposable=False, timezone_mismatch=False)
        self.assertEqual((score, hits), (0, []))


class AltMatching(unittest.IsolatedAsyncioTestCase):
    METHODS = {"cookie": True, "fingerprint": True, "ip": True}

    async def asyncSetUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.db = db.Database(os.path.join(self.dir.name, "t.db"))
        await self.db.open()
        self.future = time.time() + 1000

    async def asyncTearDown(self):
        await self.db.close()
        self.dir.cleanup()

    async def seed(self, user, **digests):
        await self.db.touch_member("1", user)
        await self.db.mark_verified("1", user, "web")
        for kind, digest in digests.items():
            await self.db.store_identifier("1", user, kind, digest, self.future)

    async def links(self, digests, *, weak_fingerprint=False, weak_ip=False, methods=None, user="99"):
        return await altmatch.find_links(self.db, "1", user, digests, methods=methods or self.METHODS,
                                         weak_fingerprint=weak_fingerprint, weak_ip=weak_ip)

    async def test_cookie_alone_is_confirmed(self):
        await self.seed("10", cookie="c1")
        self.assertEqual((await self.links({"cookie": "c1"}))[0].confidence, "confirmed")

    async def test_the_same_connection_alone_counts(self):
        await self.seed("10", ip="i1")
        links = await self.links({"ip": "i1"})
        self.assertEqual(links[0].confidence, "likely")
        self.assertEqual(altmatch.counting(links, "likely"), links)

    async def test_fingerprint_plus_connection_is_likely(self):
        await self.seed("10", fingerprint="f1", ip="i1")
        self.assertEqual((await self.links({"fingerprint": "f1", "ip": "i1"}))[0].confidence, "likely")

    async def test_two_iphones_on_mobile_data_prove_nothing(self):
        await self.seed("10", fingerprint="f1", ip="i1")
        self.assertEqual(await self.links({"fingerprint": "f1", "ip": "i1"}, weak_fingerprint=True, weak_ip=True), [])

    async def test_switched_off_methods_are_ignored(self):
        await self.seed("10", cookie="c1")
        self.assertEqual(await self.links({"cookie": "c1"}, methods={"cookie": False, "fingerprint": True, "ip": True}), [])

    async def test_device_rides_on_the_fingerprint_switch(self):
        await self.seed("10", device="d1", ip="i1")
        links = await self.links({"device": "d1", "ip": "i1"}, methods={"cookie": True, "fingerprint": False, "ip": True})
        self.assertEqual(links[0].methods, ["ip"])

    async def test_banned_account_ranks_first(self):
        await self.seed("10", cookie="c1")
        await self.seed("11", ip="i1", fingerprint="f1")
        await self.db.record_ban("1", "11")
        links = await self.links({"cookie": "c1", "ip": "i1", "fingerprint": "f1"})
        self.assertEqual(links[0].other_id, "11")
        self.assertTrue(links[0].banned)

    async def test_trusted_pair_is_skipped(self):
        await self.seed("10", cookie="c1")
        await self.db.trust_pair("1", "10", "99", "5")
        self.assertEqual(await self.links({"cookie": "c1"}), [])

    async def test_other_servers_are_invisible(self):
        await self.db.store_identifier("2", "10", "cookie", "c1", self.future)
        self.assertEqual(await self.links({"cookie": "c1"}), [])

    async def test_main_is_whoever_verified_first(self):
        await self.db.touch_member("1", "10")
        await self.db.update_member("1", "10", first_verified_at=100.0)
        await self.db.touch_member("1", "99")
        link = altmatch.Link("10", 100, "confirmed")
        await altmatch.assign_roles(self.db, "1", "99", link)
        self.assertTrue(link.other_is_main)
        await self.db.update_member("1", "99", first_verified_at=50.0)
        await altmatch.assign_roles(self.db, "1", "99", link)
        self.assertFalse(link.other_is_main)


OLD_ACCOUNT = "175928847299117063"  # created in 2016


class Engine(unittest.TestCase):
    def attempt(self, doc=None, **changes):
        base = dict(settings=doc or settings.defaults(), mode="web",
                    account=engine.Account(OLD_ACCOUNT, avatar="abc", mfa=True, email_verified=True, email_disposable=False),
                    net=NetInfo(country="US"), browser=signals.BrowserVerdict())
        base.update(changes)
        return engine.Attempt(**base)

    def test_clean_member_passes(self):
        self.assertTrue(engine.run_checks(self.attempt()).passed)

    def test_account_id_decodes_to_its_date(self):
        self.assertEqual(time.gmtime(engine.account_created_at("175928847299117063")).tm_year, 2016)

    def test_watch_records_and_lets_in(self):
        doc = settings.defaults()
        doc["checks"]["incognito"].update(enabled=True, action="watch")
        decision = engine.run_checks(self.attempt(doc, browser=signals.BrowserVerdict(private=True)))
        self.assertTrue(decision.passed)
        self.assertEqual([f.check_id for f in decision.findings], ["incognito"])

    def test_deny_stops_the_attempt(self):
        doc = settings.defaults()
        doc["checks"]["incognito"].update(enabled=True, action="deny")
        decision = engine.run_checks(self.attempt(doc, browser=signals.BrowserVerdict(private=True)))
        self.assertFalse(decision.passed)
        self.assertEqual(decision.action, "deny")

    def test_strongest_action_wins(self):
        doc = settings.defaults()
        doc["checks"]["vpn"].update(enabled=True, action="deny")
        doc["checks"]["automation"].update(enabled=True, action="ban")
        decision = engine.run_checks(self.attempt(doc, net=NetInfo(vpn=True), browser=signals.BrowserVerdict(automated=True)))
        self.assertEqual(decision.action, "ban")
        self.assertEqual(decision.primary.check_id, "automation")
        self.assertEqual(len(decision.enforced), 2)

    def test_web_only_checks_skip_button_mode(self):
        doc = settings.defaults()
        doc["checks"]["vpn"].update(enabled=True, action="ban")
        self.assertTrue(engine.run_checks(self.attempt(doc, mode="button", net=NetInfo(vpn=True))).passed)

    def test_account_age_runs_in_every_mode(self):
        doc = settings.defaults()
        doc["checks"]["account_age"].update(enabled=True, action="deny", days=100000 if False else 3650)
        young = engine.Account(str((int((time.time() * 1000) - engine.DISCORD_EPOCH_MS)) << 22), avatar="a")
        for mode in catalog.MODES:
            self.assertFalse(engine.run_checks(self.attempt(doc, mode=mode, account=young)).passed, mode)

    def test_failure_text_names_the_limit(self):
        doc = settings.defaults()
        doc["checks"]["account_age"].update(enabled=True, action="deny", days=3650)
        young = engine.Account(str((int((time.time() * 1000) - engine.DISCORD_EPOCH_MS)) << 22), avatar="a")
        self.assertIn("3650", engine.run_checks(self.attempt(doc, account=young)).primary.message)

    def test_bypass_skips_only_the_named_check(self):
        doc = settings.defaults()
        doc["checks"]["vpn"].update(enabled=True, action="deny")
        doc["checks"]["automation"].update(enabled=True, action="deny")
        decision = engine.run_checks(self.attempt(doc, net=NetInfo(vpn=True), bypass=frozenset({"vpn"}),
                                                  browser=signals.BrowserVerdict(automated=True)))
        self.assertEqual([f.check_id for f in decision.findings], ["automation"])

    def test_cooldown_is_not_a_failure(self):
        doc = settings.defaults()
        doc["core"]["cooldown"].update(enabled=True, seconds=300)
        decision = engine.run_checks(self.attempt(doc, member={"last_fail_at": time.time() - 10}))
        self.assertGreater(decision.cooldown_left, 0)
        self.assertEqual(decision.findings, [])
        self.assertFalse(decision.passed)

    def test_attempt_limit(self):
        doc = settings.defaults()
        doc["checks"]["max_attempts"].update(enabled=True, action="deny", attempts=3)
        self.assertFalse(engine.run_checks(self.attempt(doc, member={"fails": 3})).passed)
        self.assertTrue(engine.run_checks(self.attempt(doc, member={"fails": 2})).passed)

    def test_no_verified_email(self):
        doc = settings.defaults()
        doc["checks"]["disposable_email"].update(enabled=True, action="deny")
        account = engine.Account(OLD_ACCOUNT, avatar="a", email_verified=False)
        decision = engine.run_checks(self.attempt(doc, account=account))
        self.assertEqual(decision.primary.reason, "no_email")

    def test_mfa_unknown_is_not_a_failure(self):
        doc = settings.defaults()
        doc["checks"]["mfa"].update(enabled=True, action="deny")
        account = engine.Account(OLD_ACCOUNT, avatar="a", mfa=None)
        self.assertTrue(engine.run_checks(self.attempt(doc, account=account)).passed)

    def test_alt_of_a_banned_account_gets_the_harder_action(self):
        doc = settings.defaults()
        check = doc["checks"]["alt_account"]
        check.update(enabled=True, alt_action="deny", banned_alt_action="ban", main_action="kick")
        banned = altmatch.Link("10", 100, "confirmed", ["cookie"], banned=True)
        decision = engine.run_checks(self.attempt(doc, links=[banned]))
        self.assertEqual(decision.action, "ban")
        self.assertEqual(decision.main_action, "watch")

    def test_alt_of_a_good_member_gets_the_softer_action(self):
        doc = settings.defaults()
        doc["checks"]["alt_account"].update(enabled=True, alt_action="deny", banned_alt_action="ban", main_action="watch")
        link = altmatch.Link("10", 100, "confirmed", ["cookie"], verified=True)
        self.assertEqual(engine.run_checks(self.attempt(doc, links=[link])).action, "deny")

    def test_possible_alt_is_ignored_at_default_confidence(self):
        doc = settings.defaults()
        doc["checks"]["alt_account"].update(enabled=True, alt_action="ban", min_confidence="likely")
        link = altmatch.Link("10", 35, "possible", ["ip"])
        self.assertTrue(engine.run_checks(self.attempt(doc, links=[link])).passed)

    def test_geogate_block_and_allow(self):
        doc = settings.defaults()
        gate = doc["checks"]["geogate"]
        gate.update(enabled=True, action="deny", list="block", countries=["RU"])
        self.assertFalse(engine.run_checks(self.attempt(doc, net=NetInfo(country="RU"))).passed)
        self.assertTrue(engine.run_checks(self.attempt(doc, net=NetInfo(country="US"))).passed)
        gate.update(list="allow", countries=["US"])
        self.assertTrue(engine.run_checks(self.attempt(doc, net=NetInfo(country="US"))).passed)
        self.assertFalse(engine.run_checks(self.attempt(doc, net=NetInfo(country="FR"))).passed)

    def test_geogate_most_specific_rule_wins(self):
        check = {"list": "block", "countries": ["RU", "DE"], "action": "deny",
                 "overrides": {"continent:Europe": "watch", "RU": "ban"}}
        regions = {"RU": {"continent": "Europe", "region": "Eastern Europe"}, "DE": {"continent": "Europe", "region": "Western Europe"}}
        self.assertEqual(engine.geogate_action(check, "RU", regions), "ban")
        self.assertEqual(engine.geogate_action(check, "DE", regions), "watch")

    def test_geogate_log_never_holds_the_country(self):
        doc = settings.defaults()
        doc["checks"]["geogate"].update(enabled=True, action="deny", list="block", countries=["RU"])
        decision = engine.run_checks(self.attempt(doc, net=NetInfo(country="RU")))
        self.assertNotIn("RU", str(decision.findings[0].detail))

    def test_threat_uses_either_score(self):
        doc = settings.defaults()
        doc["checks"]["threat"].update(enabled=True, action="deny", bot_score=80, suspect_score=50)
        self.assertFalse(engine.run_checks(self.attempt(doc, browser=signals.BrowserVerdict(bot_score=90))).passed)
        self.assertFalse(engine.run_checks(self.attempt(doc, suspect=60)).passed)
        self.assertTrue(engine.run_checks(self.attempt(doc, suspect=10)).passed)

    def test_raid_tightens_and_leaves_the_stored_document_alone(self):
        doc = settings.apply_preset(settings.defaults(), "gentle")
        tightened = engine.effective_settings(doc, True)
        self.assertEqual(tightened["checks"]["account_age"]["action"], "kick")
        self.assertEqual((tightened["checks"]["vpn"]["enabled"], tightened["checks"]["vpn"]["action"]), (True, "deny"))
        self.assertFalse(doc["checks"]["vpn"]["enabled"])
        self.assertIs(engine.effective_settings(doc, False), doc)

    def test_every_failure_has_text_and_a_help_page(self):
        for reason in list(catalog.CHECK_IDS) + ["no_email", "cooldown"]:
            self.assertIn(reason, catalog.FAILURE_TEXT)
            self.assertIn(reason, catalog.HELP_SLUG)


class Lists(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        folder = Path(self.dir.name)
        (folder / "country-ipv4.csv").write_text("16777216,16777471,AU\n134744064,134744319,US\n")
        (folder / "asn-ipv4.csv").write_text('134744064,134744319,15169,Google LLC\n16777216,16777471,1,"Example Wireless, Inc."\n')
        (folder / "vpn-x4b-ipv4.txt").write_text("# note\n8.8.4.0/24\nnot an address\n")
        (folder / "hosting-x4b-ipv4.txt").write_text("8.8.8.0/24\n8.8.9.0/24\n")
        (folder / "tor.txt").write_text("1.2.3.4\n")
        (folder / "relay.csv").write_text("172.224.226.0/27,GB,GB-EN,London,\n2a02:26f7::/48,GB,GB-EN,London,\n")
        (folder / "disposable.txt").write_text("mailinator.com\ngmail.com\n")
        self.net = netintel.NetIntel(folder)
        self.net.lists = netintel.load_lists(folder)

    def tearDown(self):
        self.dir.cleanup()

    def test_country_and_asn(self):
        info = self.net.lookup("8.8.8.8")
        self.assertEqual((info.country, info.asn, info.org), ("US", 15169, "Google LLC"))

    def test_categories(self):
        self.assertTrue(self.net.lookup("8.8.4.4").vpn)
        self.assertTrue(self.net.lookup("8.8.8.8").hosting)
        self.assertTrue(self.net.lookup("1.2.3.4").tor)
        self.assertTrue(self.net.lookup("172.224.226.5").relay)
        self.assertTrue(self.net.lookup("2a02:26f7::1").relay)
        self.assertFalse(self.net.lookup("9.9.9.9").anonymized)

    def test_adjacent_ranges_merge(self):
        self.assertEqual(len(self.net.lists.hosting[4]), 1)

    def test_mobile_from_network_name(self):
        info = self.net.lookup("1.0.0.1")
        self.assertTrue(info.mobile)
        self.assertTrue(info.shared)

    def test_reserved_addresses_flag_nothing(self):
        for ip in ("192.168.1.1", "127.0.0.1", "::1"):
            info = self.net.lookup(ip)
            self.assertTrue(info.reserved)
            self.assertFalse(info.anonymized)

    def test_mapped_ipv4(self):
        self.assertEqual(self.net.lookup("::ffff:8.8.8.8").country, "US")

    def test_bad_address(self):
        self.assertFalse(self.net.lookup("nonsense").known)

    def test_disposable_mail(self):
        self.assertTrue(self.net.is_disposable("mailinator.com"))
        self.assertTrue(self.net.is_disposable("a.mailinator.com"))
        self.assertFalse(self.net.is_disposable("example.org"))
        self.assertFalse(self.net.is_disposable("gmail.com"))

    def test_labels_never_name_the_address(self):
        self.assertEqual(self.net.lookup("8.8.4.4").labels(), ["vpn"])


class FakeAnswer:
    def __init__(self, body):
        self.body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def json(self, content_type=None):
        return self.body


class FakeSession:
    def __init__(self, body):
        self.body, self.urls, self.params = body, [], []

    def get(self, url, params=None, timeout=None):
        self.urls.append(url)
        self.params.append(params)
        return FakeAnswer(self.body)


def proxycheck_answer(ip, **detections):
    """The shape proxycheck.io's v3 API returned on November 4, 2026."""
    return {"status": "ok", ip: {"network": {"type": "Business"}, "detections": {
        "proxy": False, "vpn": False, "tor": False, "hosting": False, "anonymous": False, "risk": 0, **detections}}, "query_time": 4}


class OutsideLookup(unittest.IsolatedAsyncioTestCase):
    async def test_proxy_vpn_tor_and_hosting_count(self):
        for name in ("proxy", "vpn", "tor", "hosting"):
            self.assertIs((await external_lookup(FakeSession(proxycheck_answer("1.2.3.4", **{name: True})), "1.2.3.4", "k"))[name], True, name)

    async def test_a_clean_address_doesnt(self):
        self.assertFalse(any((await external_lookup(FakeSession(proxycheck_answer("1.2.3.4")), "1.2.3.4", "k")).values()))

    async def test_anonymous_alone_doesnt_count_because_googles_dns_has_it(self):
        self.assertFalse(any((await external_lookup(FakeSession(proxycheck_answer("8.8.8.8", anonymous=True, risk=100)), "8.8.8.8", "k")).values()))

    async def test_ipv6_works_whatever_form_the_answer_uses(self):
        self.assertIs((await external_lookup(FakeSession(proxycheck_answer("2606:4700::1", vpn=True)), "2606:4700:0::1", "k"))["vpn"], True)

    async def test_the_key_is_sent_only_when_there_is_one(self):
        session = FakeSession(proxycheck_answer("1.2.3.4"))
        await external_lookup(session, "1.2.3.4", "abc")
        await external_lookup(session, "1.2.3.4", None)
        self.assertEqual(session.params, [{"key": "abc"}, None])
        self.assertEqual(session.urls[0], "https://proxycheck.io/v3/1.2.3.4")

    async def test_a_refusal_or_odd_answer_counts_as_no_answer(self):
        for body in ({"status": "denied", "message": "quota"}, {"status": "error"}, [], None, {"status": "ok"}):
            self.assertIsNone(await external_lookup(FakeSession(body), "1.2.3.4", "k"), body)


if __name__ == "__main__":
    unittest.main()

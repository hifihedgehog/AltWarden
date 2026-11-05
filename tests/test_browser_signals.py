"""What the browser report and the network lists do with hostile, unusual and real-world input."""
import json
import math
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_detection import CHROME_ANDROID, CHROME_WIN, clean_report, judge

from altwarden import netintel, signals

SAFARI_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"
SAFARI_IPAD = "Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
CHROME_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
FIREFOX_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
DESKTOP_LINUX = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"


class HostileNumbers(unittest.TestCase):
    def test_a_lie_count_that_is_not_finite_never_crashes_the_check(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            report = clean_report(lies={"total": value, "apis": []})
            self.assertEqual(judge(report).tamper_score, 0, value)

    def test_not_finite_numbers_count_as_absent(self):
        self.assertIsNone(signals._number(float("nan")))
        self.assertIsNone(signals._number(float("inf")))
        self.assertEqual(signals._number(float("-inf"), 7), 7)

    def test_a_huge_whole_number_does_not_crash_the_finite_test(self):
        self.assertEqual(signals._number(10 ** 400), 10 ** 400)
        self.assertEqual(judge(clean_report(lies={"total": 10 ** 400, "apis": []})).tamper_score, 100)

    def test_a_negative_lie_count_cannot_cancel_a_rewritten_tostring(self):
        report = clean_report(lies={"total": -1000, "apis": [], "toString": True})
        self.assertEqual(judge(report).tamper_score, 40)


class LooseTokens(unittest.TestCase):
    def test_darwin_is_not_windows(self):
        self.assertIsNone(signals.os_family("CFNetwork/1490 Darwin/23.0.0"))

    def test_every_real_windows_spelling_is_windows(self):
        for text in ("Win32", "Win64", "Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"):
            self.assertEqual(signals.os_family(text), "windows", text)

    def test_a_phone_model_containing_nox_is_not_an_emulator(self):
        self.assertFalse(signals.EMULATOR_MODEL.search("Lenox 5"))

    def test_the_real_emulators_still_match(self):
        for model in ("Nox", "NoxPlayer", "MEmu", "MEmuPlay", "sdk_gphone64_x86_64", "BlueStacks", "LDPlayer"):
            self.assertTrue(signals.EMULATOR_MODEL.search(model), model)


class RendererParsing(unittest.TestCase):
    def test_a_crafted_renderer_costs_no_more_than_an_ordinary_one(self):
        # Well past the 300 characters a report may carry, so the quadratic cost can't hide in timer noise.
        started = time.perf_counter()
        signals.gpu_model("ANGLE (a," + " " * 5000)
        self.assertLess(time.perf_counter() - started, 0.25)

    def test_wrappers_still_reduce_to_the_same_card(self):
        for messy in ("ANGLE (NVIDIA,  NVIDIA GeForce RTX 3080   Direct3D11 vs_5_0 ps_5_0, D3D11)",
                      "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)"):
            self.assertEqual(signals.gpu_model(messy), "NVIDIA GEFORCE RTX 3080")


class SoftwareGraphics(unittest.TestCase):
    def verdict(self, renderer):
        report = clean_report(gpu={"renderer": renderer})
        report["worker"] = {}
        return judge(report)

    def test_software_graphics_stay_a_virtual_machine_and_say_what_they_are(self):
        for renderer in ("ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)", "llvmpipe (LLVM 15.0.7, 256 bits)",
                         "Microsoft Basic Render Driver", "Microsoft Remote Display Adapter", "Citrix Indirect Display", "Mesa OffScreen"):
            verdict = self.verdict(renderer)
            self.assertTrue(verdict.vm, renderer)
            self.assertEqual(verdict.reasons["vm"], ["software graphics"], renderer)

    def test_a_hypervisor_name_says_virtual_machine(self):
        for renderer in ("VMware SVGA 3D", "VirtualBox Graphics Adapter", "Parallels Display Adapter (WDDM)"):
            verdict = self.verdict(renderer)
            self.assertTrue(verdict.vm, renderer)
            self.assertEqual(verdict.reasons["vm"], ["virtual machine graphics"], renderer)

    def test_the_module_note_credits_no_reference_with_the_list(self):
        self.assertNotIn("CreepJS and BotD list", signals.__doc__)


class WrappedFunctions(unittest.TestCase):
    def verdict(self, *apis, **changes):
        return judge(clean_report(lies={"total": len(apis), "apis": list(apis)}, **changes))

    def test_one_wrapped_canvas_function_is_privacy(self):
        for api in ("HTMLCanvasElement.toDataURL", "CanvasRenderingContext2D.getImageData"):
            verdict = self.verdict(api)
            self.assertTrue(verdict.privacy, api)
            self.assertFalse(verdict.antidetect, api)
            self.assertIn("canvas functions rewritten", verdict.reasons["privacy"])

    def test_one_family_of_wrappers_is_not_antidetect(self):
        self.assertFalse(self.verdict("Navigator.hardwareConcurrency", "Navigator.deviceMemory").antidetect)
        self.assertFalse(self.verdict("Screen.width", "Screen.height").antidetect)
        self.assertFalse(self.verdict("WebGLRenderingContext.getParameter", "WebGL2RenderingContext.getParameter").antidetect)
        self.assertFalse(self.verdict("Date.getTimezoneOffset", "Intl.DateTimeFormat.resolvedOptions").antidetect)

    def test_two_families_are_antidetect(self):
        for pair in (("Navigator.platform", "Screen.width"), ("Screen.height", "WebGLRenderingContext.getParameter"),
                     ("WebGL2RenderingContext.getParameter", "Date.getTimezoneOffset"), ("Navigator.userAgent", "Intl.DateTimeFormat.resolvedOptions")):
            self.assertTrue(self.verdict(*pair).antidetect, pair)

    def test_canvas_does_not_count_as_a_second_family(self):
        verdict = self.verdict("HTMLCanvasElement.toDataURL", "Navigator.platform")
        self.assertFalse(verdict.antidetect)
        self.assertTrue(verdict.privacy)

    def test_a_wrapped_function_still_counts_toward_tampering(self):
        self.assertEqual(self.verdict("Navigator.deviceMemory").tamper_score, 10)

    def test_canvas_noise_from_a_wrapped_function_is_privacy(self):
        verdict = self.verdict("HTMLCanvasElement.toDataURL", canvas={"noisy": True, "blocked": False})
        self.assertFalse(verdict.antidetect)
        self.assertTrue(verdict.privacy)

    def test_canvas_noise_with_no_wrapper_stays_antidetect(self):
        self.assertTrue(self.verdict(canvas={"noisy": True, "blocked": False}).antidetect)

    def test_a_worker_mismatch_needs_no_wrappers(self):
        report = clean_report()
        report["worker"]["memory"] = 4
        self.assertTrue(judge(report).antidetect)


class AgentComparison(unittest.TestCase):
    def test_a_request_agent_with_a_proxy_token_appended_is_not_a_fake(self):
        verdict = judge(clean_report(), CHROME_WIN + " CorpProxy/2.1")
        self.assertFalse(verdict.fake_ua, verdict.reasons)

    def test_a_page_agent_longer_than_the_request_is_not_a_fake(self):
        report = clean_report()
        report["nav"]["ua"] = CHROME_WIN + " Extra/1"
        report["worker"]["ua"] = CHROME_WIN + " Extra/1"
        verdict = judge(report, CHROME_WIN)
        self.assertFalse(verdict.fake_ua, verdict.reasons)

    def test_a_different_request_agent_is_still_a_fake(self):
        verdict = judge(clean_report(), FIREFOX_WIN)
        self.assertIn("page and request disagree", verdict.reasons["fake_ua"])

    def ipad(self, worker_agent):
        return clean_report(nav={"ua": SAFARI_MAC, "platform": "MacIntel", "vendor": "Apple Computer, Inc.", "cores": 8}, uad={}, gpu={"renderer": "Apple GPU"},
                            eng={"evalLen": 37}, worker={"ua": worker_agent, "platform": "iPad", "cores": 8})

    def test_an_ipad_in_desktop_mode_whose_worker_says_ipad_is_not_a_fake(self):
        verdict = judge(self.ipad(SAFARI_IPAD), SAFARI_MAC)
        self.assertFalse(verdict.fake_ua, verdict.reasons)

    def test_another_safari_version_in_the_worker_is_still_a_fake(self):
        verdict = judge(self.ipad(SAFARI_IPAD.replace("Version/18.1", "Version/17.0")), SAFARI_MAC)
        self.assertIn("page and worker disagree", verdict.reasons["fake_ua"])

    def test_apple_tokens_are_only_forgiven_on_webkit(self):
        report = clean_report(nav={"ua": CHROME_MAC, "platform": "MacIntel", "vendor": "Google Inc.", "cores": 8}, uad={}, gpu={"renderer": "Apple M2"},
                              worker={"ua": CHROME_MAC.replace("Macintosh; Intel Mac OS X 10_15_7", "iPad; CPU OS 18_1 like Mac OS X")})
        self.assertIn("page and worker disagree", judge(report, CHROME_MAC).reasons["fake_ua"])

    def test_a_chrome_worker_under_a_safari_page_is_still_a_fake(self):
        verdict = judge(self.ipad(CHROME_MAC), SAFARI_MAC)
        self.assertIn("page and worker disagree", verdict.reasons["fake_ua"])


class BotDetectors(unittest.TestCase):
    def bot(self, *fired, **nav):
        report = clean_report(bot={"bot": True, "botKind": "headless_chrome", "fired": list(fired)})
        report["nav"].update(nav)
        return judge(report)

    def test_one_weak_detector_alone_is_not_automation(self):
        for name in ("detectWindowSize", "detectRTT", "detectNotificationPermissions", "detectPluginsArray",
                     "detectMimeTypesConsistent", "detectLanguagesLengthInconsistency", "detectProductSub"):
            verdict = self.bot(name)
            self.assertFalse(verdict.automated, name)
            self.assertEqual(verdict.bot_score, 25, name)

    def test_a_named_tool_alone_is_automation(self):
        for name in ("detectWebDriver", "detectUserAgent", "detectAppVersion", "detectProcess", "detectDocumentAttributes", "detectFunctionBind",
                     "detectDistinctiveProperties", "detectErrorTrace", "detectWindowExternal", "detectWebGL", "detectEvalLengthInconsistency",
                     "detectPluginsLengthInconsistency"):
            self.assertTrue(self.bot(name).automated, name)

    def test_two_weak_detectors_together_are_automation(self):
        self.assertTrue(self.bot("detectWindowSize", "detectRTT").automated)

    def test_a_detector_this_code_has_never_heard_of_is_automation(self):
        self.assertTrue(self.bot("detectSomethingNew").automated)

    def test_a_verdict_without_a_detector_list_is_automation(self):
        self.assertTrue(judge(clean_report(bot={"bot": True, "botKind": "unknown"})).automated)

    def test_a_download_only_pdf_setting_adds_nothing(self):
        verdict = self.bot("detectPluginsLengthInconsistency", pdf=False)
        self.assertFalse(verdict.automated)
        self.assertEqual(verdict.bot_score, 0)


class CanvasNoiseByEngine(unittest.TestCase):
    def verdict(self, agent, vendor):
        report = clean_report(nav={"ua": agent, "platform": "MacIntel" if "Mac" in agent else "Win32", "vendor": vendor, "cores": 8}, uad={},
                              gpu={"renderer": ""}, eng={"evalLen": 37}, canvas={"noisy": True, "blocked": False}, worker={})
        return judge(report, agent)

    def test_noise_on_safari_stops_nobody(self):
        verdict = self.verdict(SAFARI_MAC, "Apple Computer, Inc.")
        self.assertFalse(verdict.privacy, verdict.reasons)
        self.assertFalse(verdict.antidetect, verdict.reasons)

    def test_noise_on_firefox_is_still_privacy(self):
        self.assertTrue(self.verdict(FIREFOX_WIN, "").privacy)


class TouchDevices(unittest.TestCase):
    def verdict(self, agent, platform, *, touch=0, uad=None):
        report = clean_report(nav={"ua": agent, "platform": platform, "vendor": "Google Inc.", "cores": 8, "touch": touch}, uad=uad or {}, worker={})
        return judge(report, agent)

    def test_an_android_tablet_in_desktop_mode_is_weak_evidence(self):
        self.assertTrue(self.verdict(DESKTOP_LINUX, "Linux x86_64", uad={"platform": "Android", "mobile": False}).weak_fingerprint)
        self.assertTrue(self.verdict(DESKTOP_LINUX, "Linux armv81", touch=5).weak_fingerprint)
        self.assertTrue(self.verdict(DESKTOP_LINUX, "Linux aarch64", touch=2).weak_fingerprint)

    def test_a_desktop_linux_is_strong_evidence(self):
        self.assertFalse(self.verdict(DESKTOP_LINUX, "Linux x86_64").weak_fingerprint)
        self.assertFalse(self.verdict(DESKTOP_LINUX, "Linux x86_64", touch=10).weak_fingerprint)
        self.assertFalse(self.verdict(DESKTOP_LINUX, "Linux aarch64", touch=0).weak_fingerprint)

    def test_a_report_claiming_to_be_mobile_changes_nothing_on_a_desktop_agent(self):
        report = clean_report()
        report["uad"]["mobile"] = True
        verdict = judge(report)
        self.assertFalse(verdict.weak_fingerprint)

    def test_a_report_claiming_to_be_mobile_keeps_the_developer_tools_test(self):
        report = clean_report(devtools={"timing": True})
        report["uad"]["mobile"] = True
        self.assertTrue(judge(report).devtools)

    def test_a_real_phone_agent_is_still_weak_evidence(self):
        self.assertTrue(self.verdict(CHROME_ANDROID, "Linux armv81", uad={"platform": "Android", "mobile": True}).weak_fingerprint)

    def test_a_touch_screen_chromebook_keeps_the_developer_tools_test(self):
        agent = "Mozilla/5.0 (X11; CrOS aarch64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        report = clean_report(nav={"ua": agent, "platform": "Linux aarch64", "vendor": "Google Inc.", "cores": 8, "touch": 5}, uad={}, worker={}, devtools={"timing": True})
        self.assertTrue(judge(report, agent).devtools)


class MobileNetworkNames(unittest.TestCase):
    def test_a_company_that_also_sells_home_lines_is_not_mobile_by_name(self):
        for org in ("Vodafone GmbH", "Vodafone Kabel Deutschland GmbH", "Reliance Jio Infocomm Limited", "Bharti Airtel Limited", "Claro S.A.", "Movistar Fibra",
                    "Hutchison Telecommunications", "EE Limited", "Globe Telecom Inc."):
            self.assertIsNone(netintel.MOBILE_ORG.search(org), org)

    def test_a_registered_name_that_says_mobile_still_counts(self):
        for org in ("T-Mobile USA", "Verizon Business Wireless", "Telefonica Moviles Chile", "TIM Celular S.A.", "Bell Mobility Inc.", "Orange Mobile",
                    "Claro Movil", "Vodafone Mobile", "Cellco Partnership", "Hutchison 3G UK Limited"):
            self.assertIsNotNone(netintel.MOBILE_ORG.search(org), org)


class ListFolder(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.folder = Path(self.dir.name)
        self.net = netintel.NetIntel(self.folder)

    def tearDown(self):
        self.dir.cleanup()

    def write(self, name, text):
        (self.folder / name).write_text(text, encoding="utf-8")

    def load(self):
        return netintel.load_lists(self.folder)


class ListLoading(ListFolder):
    def test_an_oversized_field_loses_that_file_and_keeps_the_rest(self):
        self.write("country-ipv4.csv", "16777216,16777471,AU\n" + "1,2," + "x" * 200_000 + "\n")
        self.write("tor.txt", "1.2.3.4\n")
        with self.assertLogs("altwarden.netintel", "WARNING"):
            lists = self.load()
        self.assertEqual(len(lists.country[4]), 0, "a half-read file must not be searched")
        self.assertEqual(len(lists.tor[4]), 1)
        self.assertEqual(lists.rows.get("country-ipv4.csv", 0), 0)
        self.assertEqual(lists.rows["tor.txt"], 1)

    def test_a_number_past_64_bits_loses_only_its_row(self):
        self.write("country-ipv4.csv", f"16777216,16777471,AU\n{2 ** 70},{2 ** 70},US\n-5,-1,US\n")
        lists = self.load()
        self.assertEqual(len(lists.country[4]), 1)
        self.assertEqual(lists.rows["country-ipv4.csv"], 1)

    def test_a_file_that_cannot_be_read_doesnt_stop_the_load(self):
        self.write("tor.txt", "1.2.3.4\n")
        (self.folder / "relay.csv").mkdir()
        with self.assertLogs("altwarden.netintel", "WARNING"):
            lists = self.load()
        self.assertEqual(lists.rows["tor.txt"], 1)

    async def test_startup_survives_a_damaged_list(self):
        self.write("asn-ipv4.csv", "1,2," + "x" * 200_000 + "\n")
        self.write("tor.txt", "1.2.3.4\n")
        with self.assertLogs("altwarden.netintel", "WARNING"):
            await self.net.load()
        self.assertTrue(self.net.ready)

    def test_a_web_page_in_a_list_counts_for_nothing(self):
        page = "<!doctype html>\n<html><body>Rate limited, try again.</body></html>\n"
        for name in ("tor.txt", "disposable.txt", "relay.csv", "vpn-x4b-ipv4.txt", "country-ipv4.csv", "asn-ipv4.csv"):
            self.write(name, page)
        lists = self.load()
        for name in ("tor.txt", "disposable.txt", "relay.csv", "vpn-x4b-ipv4.txt", "country-ipv4.csv", "asn-ipv4.csv"):
            self.assertEqual(lists.rows[name], 0, name)
        self.assertEqual(lists.disposable, set())

    def test_every_list_still_loads_what_it_held(self):
        self.write("country-ipv4.csv", "16777216,16777471,AU\n")
        self.write("asn-ipv4.csv", '16777216,16777471,1,"Example Wireless, Inc."\n')
        self.write("vpn-x4b-ipv4.txt", "# note\n8.8.4.0/24\nnot an address\n")
        self.write("vpn-x4b-ipv6.txt", "2001:db8::/32\n")
        self.write("vpn-open-mullvad.txt", "9.9.9.0/24\n")
        self.write("hosting-x4b-ipv4.txt", "8.8.8.0/24\n8.8.9.0/24\n")
        self.write("tor.txt", "1.2.3.4\n")
        self.write("relay.csv", "172.224.226.0/27,GB,GB-EN,London,\n2a02:26f7::/48,GB,GB-EN,London,\n")
        self.write("disposable.txt", "# note\nmailinator.com\nGmail.com\nxn--80ak6aa92e.com\n")
        lists = self.load()
        self.assertEqual(lists.rows, {"country-ipv4.csv": 1, "asn-ipv4.csv": 1, "vpn-x4b-ipv4.txt": 1, "vpn-x4b-ipv6.txt": 1, "vpn-open-mullvad.txt": 1,
                                      "hosting-x4b-ipv4.txt": 2, "tor.txt": 1, "relay.csv": 2, "disposable.txt": 3})
        self.net.lists = lists
        info = self.net.lookup("9.9.9.9")
        self.assertTrue(info.vpn)
        self.assertEqual(self.net.lookup("1.0.0.5").org, "Example Wireless, Inc.")
        self.assertIn(1, lists.mobile_asns)
        self.assertTrue(self.net.is_disposable("mailinator.com"))
        self.assertFalse(self.net.is_disposable("gmail.com"))

    def test_a_list_reports_its_name_age_and_rows(self):
        self.write("tor.txt", "1.2.3.4\n5.6.7.8\n")
        os.utime(self.folder / "tor.txt", (time.time() - 3 * 86400, time.time() - 3 * 86400))
        self.net.lists = self.load()
        status = {row["name"]: row for row in self.net.list_status()}
        self.assertEqual(set(status), set(netintel.SOURCES))
        self.assertEqual(status["tor.txt"]["rows"], 2)
        self.assertAlmostEqual(status["tor.txt"]["age_days"], 3, delta=0.1)
        self.assertEqual(status["relay.csv"], {"name": "relay.csv", "age_days": None, "rows": 0})
        json.dumps(self.net.list_status())

    def test_every_source_has_a_minimum(self):
        self.assertEqual(set(netintel.MIN_ROWS), set(netintel.SOURCES))


class ListDownload(ListFolder):
    class Content:
        def __init__(self, body):
            self.body = body

        async def iter_chunked(self, size):
            yield self.body

    class Reply:
        def __init__(self, body):
            self.content = ListDownload.Content(body)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def raise_for_status(self):
            pass

    class Session:
        def __init__(self, body):
            self.body = body

        def get(self, url, headers=None):
            return ListDownload.Reply(self.body)

    async def fetch(self, name, body):
        return await self.net._fetch(self.Session(body), name, "http://127.0.0.1/never")

    async def test_a_web_page_doesnt_replace_a_good_list(self):
        self.write("tor.txt", "1.2.3.4\n")
        with self.assertRaises(ValueError):
            await self.fetch("tor.txt", b"<html>" + b"<p>Rate limited</p>\n" * 200 + b"</html>")
        self.assertEqual((self.folder / "tor.txt").read_text(), "1.2.3.4\n")
        self.assertEqual(list(self.folder.glob("*.part")), [])

    async def test_too_few_rows_dont_replace_a_good_list(self):
        self.write("tor.txt", "1.2.3.4\n")
        with self.assertRaises(ValueError):
            await self.fetch("tor.txt", "".join(f"1.2.3.{i}\n" for i in range(netintel.MIN_ROWS["tor.txt"] - 1)).encode())
        self.assertEqual((self.folder / "tor.txt").read_text(), "1.2.3.4\n")

    async def test_a_body_that_cannot_be_parsed_doesnt_replace_a_good_list(self):
        self.write("country-ipv4.csv", "16777216,16777471,AU\n")
        with self.assertRaises(Exception):
            await self.fetch("country-ipv4.csv", b"1,2," + b"x" * 200_000 + b"\n")
        self.assertEqual((self.folder / "country-ipv4.csv").read_text(), "16777216,16777471,AU\n")
        self.assertEqual(list(self.folder.glob("*.part")), [])

    async def test_enough_good_rows_replace_the_list(self):
        self.write("vpn-open-riseupvpn.txt", "1.2.3.4\n")
        body = "".join(f"9.9.9.{i}\n" for i in range(netintel.MIN_ROWS["vpn-open-riseupvpn.txt"])).encode()
        self.assertEqual(await self.fetch("vpn-open-riseupvpn.txt", body), 1)
        self.assertEqual((self.folder / "vpn-open-riseupvpn.txt").read_bytes(), body)

    async def test_the_minimums_pass_the_lists_as_they_are_published_today(self):
        # Row counts read from the published lists on 2026-11-04. The smallest is riseupvpn, at 20.
        published = {"country-ipv4.csv": 297467, "country-ipv6.csv": 286152, "asn-ipv4.csv": 447088, "asn-ipv6.csv": 127261, "vpn-x4b-ipv4.txt": 11067,
                     "vpn-x4b-ipv6.txt": 648, "hosting-x4b-ipv4.txt": 44669, "hosting-x4b-ipv6.txt": 8008, "tor.txt": 1245, "relay.csv": 285129, "disposable.txt": 10123,
                     "vpn-open-airvpn.txt": 2000, "vpn-open-ivpn.txt": 267, "vpn-open-mullvad.txt": 1122, "vpn-open-nordvpn.txt": 7230, "vpn-open-ovpn.txt": 96,
                     "vpn-open-pia.txt": 1497, "vpn-open-protonvpn.txt": 1380, "vpn-open-riseupvpn.txt": 20, "vpn-open-surfshark.txt": 278, "vpn-open-windscribe.txt": 1044}
        for name, rows in published.items():
            self.assertLessEqual(netintel.MIN_ROWS[name], rows // 2, name)


class DisposableDomains(ListFolder):
    def test_a_unicode_domain_matches_its_listed_ascii_form(self):
        self.write("disposable.txt", "xn--bcher-kva.example\n")
        self.net.lists = self.load()
        self.assertTrue(self.net.is_disposable("bücher.example"))
        self.assertTrue(self.net.is_disposable("mail.bücher.example"))
        self.assertTrue(self.net.is_disposable("xn--bcher-kva.example"))

    def test_a_name_idna_cannot_encode_is_only_compared_as_written(self):
        self.write("disposable.txt", "mailinator.com\n")
        self.net.lists = self.load()
        self.assertFalse(self.net.is_disposable(("x" * 70) + ".example"))
        self.assertFalse(self.net.is_disposable("a..b"))


class IncompleteReports(unittest.TestCase):
    ALWAYS_SENT = ("nav", "scr", "tz", "gpu", "eng", "lies", "canvas", "privacy", "devtools", "act")

    def assert_automated(self, verdict, why="incomplete browser report"):
        self.assertTrue(verdict.automated, verdict.reasons)
        self.assertIn(why, verdict.reasons["automated"])

    def test_the_smallest_report_a_script_could_send_is_automated(self):
        self.assert_automated(judge({"nav": {"ua": CHROME_WIN}, "eng": {"evalLen": 33}}))

    def test_a_missing_section_is_automated(self):
        for name in self.ALWAYS_SENT:
            report = clean_report()
            del report[name]
            self.assert_automated(judge(report))

    def test_an_empty_user_agent_is_automated(self):
        report = clean_report()
        report["nav"]["ua"] = ""
        self.assert_automated(judge(report))

    def test_a_section_of_the_wrong_type_is_automated(self):
        for name in self.ALWAYS_SENT:
            self.assert_automated(judge(clean_report(**{name: []})))
            self.assert_automated(judge(clean_report(**{name: None})))

    def test_a_section_without_its_field_is_automated(self):
        for name, field in (("nav", "ua"), ("scr", "w"), ("tz", "offset"), ("gpu", "renderer"), ("eng", "evalLen"), ("lies", "total"), ("canvas", "noisy"),
                            ("devtools", "timing"), ("act", "ms")):
            report = clean_report()
            del report[name][field]
            self.assert_automated(judge(report))

    def test_a_field_of_the_wrong_type_is_automated(self):
        for name, field, junk in (("nav", "ua", 5), ("scr", "w", "wide"), ("tz", "offset", "x"), ("gpu", "renderer", 7), ("eng", "evalLen", "33"), ("lies", "total", "many"),
                                  ("canvas", "noisy", 1), ("devtools", "timing", "no"), ("act", "ms", float("nan"))):
            report = clean_report()
            report[name][field] = junk
            self.assert_automated(judge(report))

    def test_a_section_that_failed_in_the_browser_is_not_automated(self):
        for name in self.ALWAYS_SENT:
            verdict = judge(clean_report(**{name: {"failed": True}}))
            self.assertFalse(verdict.automated, (name, verdict.reasons))

    def test_three_failed_sections_are_still_a_broken_browser(self):
        report = clean_report(scr={"failed": True}, tz={"failed": True}, lies={"failed": True})
        self.assertFalse(judge(report).automated)

    def test_a_report_of_nothing_but_failures_is_automated(self):
        self.assert_automated(judge({name: {"failed": True} for name in self.ALWAYS_SENT}))
        self.assert_automated(judge(clean_report(scr={"failed": True}, tz={"failed": True}, lies={"failed": True}, act={"failed": True})))

    def test_a_clean_report_passes(self):
        self.assertFalse(judge(clean_report()).automated)

    def test_the_sections_that_can_be_empty_stay_optional(self):
        for name in ("fp", "bot", "private", "uad", "worker", "conn"):
            report = clean_report()
            report.pop(name, None)
            self.assertFalse(judge(report).automated, name)
            report[name] = None
            self.assertFalse(judge(report).automated, name)

    def test_no_device_cookie_is_automated_when_the_caller_says_so(self):
        verdict = signals.evaluate(clean_report(), {"User-Agent": CHROME_WIN}, device_cookie=False)
        self.assert_automated(verdict, "no device cookie")
        self.assertEqual(verdict.bot_score, 100)

    def test_a_device_cookie_changes_nothing(self):
        self.assertFalse(signals.evaluate(clean_report(), {"User-Agent": CHROME_WIN}, device_cookie=True).automated)
        self.assertFalse(signals.evaluate(clean_report(), {"User-Agent": CHROME_WIN}).automated)


class MissingLibraries(unittest.TestCase):
    def test_a_blocked_library_is_privacy(self):
        for section in ("fp", "bot", "private"):
            verdict = judge(clean_report(**{section: {"blocked": True}}))
            self.assertTrue(verdict.privacy, section)
            self.assertFalse(verdict.automated, section)
            self.assertEqual(len(verdict.reasons["privacy"]), 1, section)

    def test_a_slow_library_sets_nothing(self):
        for section in ("fp", "bot", "private"):
            for shape in ({"timeout": True}, {"failed": True}, None):
                verdict = judge(clean_report(**{section: shape}))
                self.assertFalse(verdict.privacy, (section, shape))
                self.assertFalse(verdict.automated, (section, shape))

    def test_only_a_true_value_counts_as_blocked(self):
        self.assertFalse(judge(clean_report(fp={"blocked": "yes"})).privacy)


class Graphics(unittest.TestCase):
    def test_no_webgl_at_all_is_not_hiding(self):
        report = clean_report(gpu={"renderer": ""}, privacy={"gpuHidden": False})
        report["worker"] = {}
        self.assertFalse(judge(report).privacy)

    def test_a_context_without_the_debug_extension_is_hiding(self):
        report = clean_report(gpu={"renderer": "WebKit WebGL"}, privacy={"gpuHidden": True})
        report["worker"] = {}
        self.assertIn("graphics details hidden", judge(report).reasons["privacy"])


class BraveShields(unittest.TestCase):
    def test_shields_down_is_clean(self):
        verdict = judge(clean_report(privacy={"brave": True, "braveMode": "allow"}))
        self.assertFalse(verdict.privacy, verdict.reasons)

    def test_shields_up_is_privacy(self):
        for mode in ("standard", "strict"):
            verdict = judge(clean_report(privacy={"brave": True, "braveMode": mode}))
            self.assertIn("Brave Shields", verdict.reasons["privacy"], mode)

    def test_a_mode_it_could_not_read_is_clean(self):
        self.assertFalse(judge(clean_report(privacy={"brave": True, "braveMode": "unknown"})).privacy)

    def test_a_noisy_canvas_means_shields_are_up_whatever_the_mode_says(self):
        for mode in ("allow", "unknown", None):
            verdict = judge(clean_report(privacy={"brave": True, "braveMode": mode}, canvas={"noisy": True, "blocked": False}))
            self.assertFalse(verdict.antidetect, mode)
            self.assertTrue(verdict.privacy, mode)


class CollectedFields(unittest.TestCase):
    """The browser sends what the server reads. This reads the collector's source, and the real browser run proves it behaves."""

    def setUp(self):
        static = Path(signals.__file__).parent / "web" / "static"
        self.collector = (static / "js" / "collector.js").read_text(encoding="utf-8")
        self.probe = (static / "js" / "workers" / "probe.js").read_text(encoding="utf-8")
        self.verify = (static / "verify.html").read_text(encoding="utf-8")
        self.vendor = {path.name for path in (static / "vendor").iterdir() if path.is_file()}

    def test_nothing_the_server_never_reads_is_collected(self):
        for field in ("navigator.languages", "innerWidth", "outerWidth", "devicePixelRatio", "UNMASKED_VENDOR_WEBGL", "gl.VENDOR", "brands", "bitness", "uaFullVersion",
                      "effectiveType", "confidence", "browserName", "v: 1"):
            self.assertNotIn(field, self.collector, field)
        self.assertNotIn("languages", self.probe)

    def test_each_field_the_collector_still_sends_has_a_reader(self):
        source = Path(signals.__file__).read_text(encoding="utf-8")
        for field in ("cores", "memory", "touch", "pdf", "modern", "platform", "vendor", "webdriver", "architecture", "model", "platformVersion", "intlOffset",
                      "gpuHidden", "braveMode"):
            self.assertIn(f'"{field}"', source, field)

    def test_vendored_files_have_neutral_names_with_their_versions(self):
        self.assertEqual(self.vendor, {"a-5.3.0.min.js", "b-2.0.0.esm.js", "c-1.9.0.min.js"})
        for reference in ("/static/vendor/a-5.3.0.min.js", "/static/vendor/c-1.9.0.min.js"):
            self.assertIn(reference, self.verify)
        self.assertIn("/static/vendor/b-2.0.0.esm.js", self.collector)

    def test_no_old_vendored_name_is_left(self):
        root = Path(signals.__file__).parent.parent
        for folder, pattern in ((root / "scripts", "*.py"), (root / "altwarden" / "web" / "static", "*.html"), (root / "altwarden" / "web" / "static" / "js", "*.js"),
                                (root / "altwarden", "*.py")):
            for path in folder.glob(pattern):
                text = path.read_text(encoding="utf-8")
                for old in ("fingerprintjs-5.3.0", "botd-2.0.0", "detectincognito-1.9.0"):
                    self.assertNotIn(old, text, path.name)


class Translations(unittest.TestCase):
    """The page's behavior is proved in a real browser. These hold what a browser run wouldn't notice: a language missing a string."""

    STATIC = Path(signals.__file__).parent / "web" / "static"
    LANGUAGES = ("de", "es", "fr", "ja", "ko", "pt", "ru", "zh")

    def english(self):
        return json.loads((self.STATIC / "i18n" / "en.json").read_text(encoding="utf-8"))

    def test_every_language_holds_every_string(self):
        english = self.english()
        for code in self.LANGUAGES:
            strings = json.loads((self.STATIC / "i18n" / f"{code}.json").read_text(encoding="utf-8"))
            self.assertEqual(set(strings), set(english), code)
            self.assertTrue(all(value.strip() for value in strings.values()), code)

    def test_a_translation_keeps_its_placeholders(self):
        for code in self.LANGUAGES:
            strings = json.loads((self.STATIC / "i18n" / f"{code}.json").read_text(encoding="utf-8"))
            for key, value in strings.items():
                self.assertEqual(sorted(re.findall(r"\{\w+\}", key)), sorted(re.findall(r"\{\w+\}", value)), (code, key))

    def test_every_string_the_page_asks_for_is_listed(self):
        source = (self.STATIC / "js" / "verify.js").read_text(encoding="utf-8")
        english = set(self.english())
        for text in re.findall(r'\bt\("((?:[^"\\]|\\.)*)"', source):
            self.assertIn(text, english)

    def test_what_the_server_sends_the_page_is_listed(self):
        root = Path(signals.__file__).parent
        service = (root / "service.py").read_text(encoding="utf-8")
        app = (root / "web" / "app.py").read_text(encoding="utf-8")
        english = set(self.english())
        sent = [text for pair in re.findall(r'Result\("problem", "([^"]+)", "([^"]+)"', service) for text in pair]
        sent += re.findall(r'return None, "([^"]+)"', service) + re.findall(r'json_error\(\d+, "([^"]+)"', app)
        self.assertGreater(len(sent), 20)
        for text in sent:
            self.assertIn(text, english)


if __name__ == "__main__":
    unittest.main()

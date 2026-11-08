"""What a member can do about each check that stopped them, in plain steps.

The verify page shows the fixes for an attempt, with the steps for the member's own device and browser first.
The failure DM carries the same steps, and each help page shows every version. Buttons are named the way each
app labels them, from these pages, read in November 2026:

  Discord    support.discord.com articles 25966860846231 (passkeys), 26304482627095 (authenticator apps),
             4423385681175 (changing your email) and 4403147417623 (profiles)
  Apple      the iPhone and Mac user guides on iCloud Private Relay
  Brave      support.brave.app article 360023646212 (Shields for one site)
  Chrome     support.google.com/meet/answer/9302964 (graphics acceleration)
  Edge       learn.microsoft.com, troubleshoot/microsoft-edge/performance/edge-crashes-fails-to-launch
  Firefox    support.mozilla.org, Enhanced Tracking Protection and hardware acceleration articles

The text is English, and the page translates it through the strings in static/i18n.
"""
from __future__ import annotations

from dataclasses import dataclass

PHONES = frozenset({"android", "ios"})
COMPUTERS = frozenset({"windows", "mac", "linux", "chromeos"})
ANY = frozenset()

# What the page says once the steps are done. Fixed in Discord means the next try signs in again, so Discord can say what changed.
SIGN_IN_AGAIN, TRY_AGAIN, NOTHING = "signin", "retry", None


@dataclass(frozen=True)
class Way:
    """One set of steps, for the systems, browsers and signs it fits. An empty set fits anything."""

    heading: str
    steps: tuple[str, ...]
    title: str | None = None  # in place of the fix's own, when this way is the one shown first
    why: str | None = None
    systems: frozenset = ANY
    browsers: frozenset = ANY
    signs: frozenset = ANY
    fallback: bool = False  # also answers a finding whose signs no way names
    in_dm: bool = True

    def fits(self, system: str | None, browser: str | None) -> bool:
        return (not self.systems or system is None or system in self.systems) and (not self.browsers or browser in self.browsers)


@dataclass(frozen=True)
class Fix:
    title: str
    why: str
    ways: tuple[Way, ...]
    after: str | None = TRY_AGAIN
    # Discord's own settings can be on another device than the browser, so every device's steps go along.
    every_way: bool = False


APP_SETTINGS = "Tap your profile picture at the bottom right, then the gear at the top right, then Account."
COMPUTER_SETTINGS = "Click the gear next to your name at the bottom left. User Settings opens on My Account."
BACKUP_CODES = "Discord shows backup codes. Save them somewhere safe."
SAME_IN_BROWSER = "If your browser has a VPN of its own, turn that off too."
DRIVER = "If it's already on, update your graphics driver, or open the link on another device."
ACCELERATION = ("Turn on graphics acceleration in your browser",
                "Your browser is drawing without your graphics card, which is how a virtual machine looks to this server.")
NO_TOR = "Open the link in a regular browser, not Tor Browser."
RELAY = ("Turn off iCloud Private Relay", "iCloud Private Relay hides your connection the way a VPN does, so this server can't accept it.")
BRAVE = ("Turn off Brave Shields for this page",
         "Brave Shields hides details this server uses to tell devices apart. You can switch Shields back up once you're verified.")
REGULAR_EMAIL = "Open the email Discord sends to the new address, and verify it."

FIXES: dict[str, Fix] = {
    "mfa": Fix(
        "Turn on two-factor login in Discord",
        "Accounts with two-factor login are much harder to steal or mass-produce.",
        (
            Way("In the Discord app on a phone or tablet", (
                "Open the Discord app. Tap your profile picture at the bottom right, then the gear at the top right.",
                "Tap Account, then Security Keys, then Add.",
                "Your phone offers to save a passkey. Confirm with your fingerprint, face or screen lock, then tap Finish.",
                BACKUP_CODES), systems=PHONES),
            Way("In Discord on a computer", (
                COMPUTER_SETTINGS,
                "Under Password and Authentication, click Register a Security Key, then follow the prompts.",
                "Your computer saves a passkey and asks for your fingerprint, face, PIN or phone to confirm it.",
                BACKUP_CODES), systems=COMPUTERS),
            Way("With a code app instead", (
                "In the same place in Discord, choose Enable Authenticator App.",
                "Install a code app such as Google Authenticator or Authy, then add Discord to it with the key or QR code Discord shows.",
                "Type the 6-digit code from the app into Discord to finish."), in_dm=False),
        ),
        after=SIGN_IN_AGAIN, every_way=True),
    "no_email": Fix(
        "Verify your email in Discord",
        "This server checks that accounts use a real email address, and Discord says yours isn't verified.",
        (
            Way("In the Discord app on a phone or tablet", (
                "Find the email Discord sent you, and press the button in it to verify your address. Check your spam folder too.",
                "If it never came, tap your profile picture at the bottom right, then the gear at the top right, then Account.",
                "Tap your email address and change it to one you can open. Discord sends a new email to verify."), systems=PHONES),
            Way("In Discord on a computer", (
                "Find the email Discord sent you, and press the button in it to verify your address. Check your spam folder too.",
                "If it never came, click the gear next to your name at the bottom left. User Settings opens on My Account.",
                "Press Edit next to your email and change it to one you can open. Discord sends a new email to verify."), systems=COMPUTERS),
        ),
        after=SIGN_IN_AGAIN, every_way=True),
    "disposable_email": Fix(
        "Use a regular email address in Discord",
        "Temporary inboxes make it easy to create accounts in bulk, so this server turns them away.",
        (
            Way("In the Discord app on a phone or tablet", (
                APP_SETTINGS,
                "Tap your email address and change it to one from a regular provider, such as Gmail, Outlook or iCloud.",
                REGULAR_EMAIL), systems=PHONES),
            Way("In Discord on a computer", (
                COMPUTER_SETTINGS,
                "Press Edit next to your email and change it to one from a regular provider, such as Gmail, Outlook or iCloud.",
                REGULAR_EMAIL), systems=COMPUTERS),
        ),
        after=SIGN_IN_AGAIN, every_way=True),
    "avatar": Fix(
        "Add a profile picture in Discord",
        "Throwaway accounts rarely set one, so this server requires it.",
        (
            Way("In the Discord app on a phone or tablet", (
                "Tap the round profile icon at the bottom right, then Edit Profile.",
                "Tap the picture, choose an image, and save your changes."), systems=PHONES),
            Way("In Discord on a computer", (
                "Click the gear next to your name at the bottom left, then Profiles.",
                "Press Change Avatar, pick an image, then press Apply and Save Changes."), systems=COMPUTERS),
        ),
        after=SIGN_IN_AGAIN, every_way=True),
    "alt_account": Fix(
        "This account looks linked to another",
        "Something about this browser or connection matches another account in this server. That can happen to people who share a home or a computer.",
        (Way("What to do", (
            "If it's a mistake, press Appeal to staff if the page shows it, and explain. Saying that you share a home or computer helps.",
            "Staff decide, and they can mark the two accounts as different people.")),),
        after=NOTHING),
    "vpn": Fix(
        "Turn off your VPN",
        "VPNs and proxies make it easy to dodge bans, so this server limits them. Data centers, Tor and iCloud Private Relay count too.",
        (
            Way("On an iPhone or iPad", (
                "Open Settings, tap your name, then iCloud, then Private Relay.",
                "Tap Private Relay, then Turn Off Until Tomorrow. It turns itself back on within a day."),
                *RELAY, systems=frozenset({"ios"}), signs=frozenset({"private relay"})),
            Way("On a Mac", (
                "Open System Settings and click your name at the top of the sidebar.",
                "Click iCloud, then Private Relay. Turn it off, choose Turn Off Until Tomorrow, then click Done."),
                *RELAY, systems=frozenset({"mac"}), signs=frozenset({"private relay"})),
            Way("If you use Tor Browser", (NO_TOR,), "Open the link without Tor", "This server doesn't accept connections through Tor.",
                signs=frozenset({"tor"})),
            Way("If you use a VPN app", (
                "Turn off your VPN or proxy while you verify. You can turn it back on afterward.",
                SAME_IN_BROWSER), signs=frozenset({"vpn"}), fallback=True),
            Way("If you don't use a VPN", (
                "Turn off any VPN, proxy or privacy app, such as Cloudflare WARP, while you verify.",
                SAME_IN_BROWSER,
                "Use your home connection if you can. School and work networks can look like a VPN."),
                "Your connection comes from a data center", "Your internet address belongs to a data center, which is where VPNs and proxies run.",
                signs=frozenset({"data center"})),
        )),
    "mobile_data": Fix(
        "Mobile data isn't accepted here",
        "Mobile networks hand out new addresses all the time, so this server asks for another connection.",
        (Way("What to do", ("Connect to Wi-Fi and try again.",)),),
        after=NOTHING),
    "automation": Fix(
        "Your browser looks automated",
        "Scripts that drive a browser are used to verify accounts in bulk.",
        (Way("What to do", ("Open the link in a normal browser such as Chrome, Edge, Safari or Firefox.", "Turn off extensions that automate pages.")),)),
    "antidetect": Fix(
        "Your browser hides what device it's on",
        "Tools that invent a new device for every profile let one person run many accounts. Some privacy tools can look like one by mistake.",
        (Way("What to do", ("Use a normal browser with its default settings.", "Turn off extensions that change what your browser reports.")),)),
    "tampering": Fix(
        "Your browser looks modified",
        "Built-in browser functions were rewritten, usually by an extension.",
        (Way("What to do", ("Turn off extensions that change or hide browser details, or try a browser with none.",)),)),
    "fake_ua": Fix(
        "Your browser is reporting the wrong identity",
        "It claims to be a different browser or system than it is, usually because of an extension.",
        (Way("What to do", ("Turn off user agent switchers.", "Try again in a normal browser.")),)),
    "devtools": Fix(
        "Developer tools are open",
        "This server doesn't accept verification with developer tools open.",
        (Way("What to do", ("Close the developer tools panel. F12 opens and closes it, or Command+Option+I on a Mac.",)),)),
    "incognito": Fix(
        "This is a private window",
        "Private windows throw away cookies, which helps people dodge alt detection.",
        (
            Way("On a computer", (
                "Copy this page's address from the address bar.",
                "Open a normal window with Ctrl+N, or Command+N on a Mac. Paste the address there and sign in again."), systems=COMPUTERS),
            Way("On a phone or tablet", (
                "Copy this page's address.",
                "Switch to a normal tab, not a private or incognito one. Paste the address there and sign in again."), systems=PHONES),
            Way("In a Chrome guest window", (
                "Guest mode in Chrome can read as a private window too. Open a regular browser profile, or use your own device.",)),
        ),
        after=NOTHING),
    "privacy": Fix(
        "Your browser is blocking device details",
        "Strict privacy settings hide what this server uses to tell devices apart. There's nothing wrong with using them.",
        (
            Way("In Brave on a computer", (
                "Click the lion icon at the right end of the address bar.",
                "Switch Shields down for this site. The page reloads."),
                *BRAVE, systems=COMPUTERS, signs=frozenset({"Brave Shields"})),
            Way("In Brave on a phone", (
                "Tap the lion icon in the address bar.",
                "Switch Shields down for this site, then reload the page."),
                *BRAVE, systems=PHONES, signs=frozenset({"Brave Shields"})),
            Way("In Firefox", (
                "If this is a private window, open the link in a normal Firefox window instead.",
                "Click the shield icon at the left of the address bar, then switch off Enhanced Tracking Protection for this site. The page reloads."),
                "Turn off Firefox's extra protection for this page",
                "Firefox changes what this page measures in private windows and with strict tracking protection.",
                signs=frozenset({"canvas randomized"})),
            Way("If you set your browser to resist fingerprinting", (
                "Open the link in a browser with normal settings, such as Chrome, Edge, Safari or Firefox.",),
                signs=frozenset({"fingerprint resistance on"})),
            Way("In Tor Browser", (NO_TOR,), "Open the link without Tor", "Tor Browser hides what this server checks.",
                signs=frozenset({"Tor Browser"})),
            Way("If you use a privacy extension", (
                "Turn the extension off for this site, or open the link in another browser that doesn't have it.",),
                "Turn off your privacy extension for this page",
                "An extension, such as CanvasBlocker or JShelter, is hiding or changing what this page measures.",
                signs=frozenset({"canvas blocked", "canvas functions rewritten", "graphics details hidden"})),
            Way("If you use an ad blocker or content blocker", (
                "Allow this site in your blocker, or pause it, then reload the page.",
                "DNS filters such as NextDNS or Pi-hole can block it too."),
                "Let this page load in full", "A blocker stopped part of this page from loading.",
                signs=frozenset({"fingerprint library blocked", "automation library blocked", "private window library blocked"})),
            Way("Other privacy settings", (
                "Turn off fingerprint protection or Brave Shields for this site.",
                "If a blocker or extension is stopping this page's verification scripts, allow them on this site.",
                "Or use a browser with default settings for this one step."), fallback=True),
        )),
    "threat": Fix(
        "This attempt scored too high on risk",
        "Several small signs added up, such as a VPN, extensions or an unusual setup.",
        (Way("What to do", ("Try a normal browser with no extensions on your home connection.",)),)),
    "vm": Fix(
        "This looks like a virtual machine",
        "Virtual machines can be reset in seconds, which makes them an easy way to look like a new device. Remote desktops and turned-off graphics acceleration can look like one too.",
        (
            Way("In Chrome or Brave", (
                "Open your browser's Settings, then System.",
                "Turn on Use graphics acceleration when available, then restart the browser.",
                DRIVER), *ACCELERATION, browsers=frozenset({"chrome"}), signs=frozenset({"software graphics"})),
            Way("In Edge", (
                "Open Settings, then System and performance.",
                "Turn on Use graphics acceleration when available, then restart Edge.",
                DRIVER), *ACCELERATION, browsers=frozenset({"edge"}), signs=frozenset({"software graphics"})),
            Way("In Firefox", (
                "Open Settings. Under General, find Performance.",
                "Uncheck Use recommended performance settings, then check Use hardware acceleration when available and restart Firefox.",
                DRIVER), *ACCELERATION, browsers=frozenset({"firefox"}), signs=frozenset({"software graphics"})),
            Way("In another browser", (
                "Turn on hardware or graphics acceleration in your browser's settings, then restart the browser.",
                DRIVER), *ACCELERATION, signs=frozenset({"software graphics"})),
            Way("In a virtual machine or remote desktop", (
                "Open the link on your own device, not inside a virtual machine or a remote desktop.",),
                "Open the link on your own device", "This page is running inside a virtual machine or a remote desktop.",
                signs=frozenset({"virtual machine graphics"}), fallback=True),
        )),
    "rooted": Fix(
        "This phone looks emulated or modified",
        "Emulators and modified phones let one person look like many. Custom firmware, or a phone reporting a model that doesn't fit its hardware, can trigger this.",
        (Way("What to do", ("Verify from a regular phone or computer.",)),),
        after=NOTHING),
}


def _signs(detail: dict) -> frozenset:
    """What a check recorded about itself: a browser check's signs, or the VPN check's kinds of network."""
    found = []
    for key in ("signs", "network"):
        value = detail.get(key)
        if isinstance(value, list):
            found += [item for item in value if isinstance(item, str)]
    return frozenset(found)


def _relevant(fix: Fix, signs: frozenset) -> list[Way]:
    """The ways that answer these signs. With none named, the fallback ways and those for any sign answer instead."""
    named = [way for way in fix.ways if way.signs and way.signs & signs]
    if named:
        return named
    unsigned = [way for way in fix.ways if not way.signs or way.fallback]
    return unsigned or list(fix.ways)


def ordered_ways(fix: Fix, *, signs: frozenset = ANY, system: str | None = None, browser: str | None = None) -> list[Way]:
    """The ways a member should see, best first. Ways for another device follow only where Discord may be on one."""
    relevant = _relevant(fix, signs)
    fitting = [way for way in relevant if way.fits(system, browser)]
    if not fitting:
        return relevant
    best = fitting[0]
    return [best] + [way for way in (relevant if fix.every_way else fitting) if way is not best]


def for_findings(findings: list, *, system: str | None = None, browser: str | None = None) -> list[dict]:
    """The fixes for the checks an attempt failed, in the order the checks ran, for the page and the DM."""
    fixes = []
    for finding in findings:
        fix = FIXES.get(finding.reason)
        if fix is None:
            continue
        ways = ordered_ways(fix, signs=_signs(finding.detail), system=system, browser=browser)
        best = ways[0]
        fixes.append({"check": finding.reason, "title": best.title or fix.title, "why": best.why or fix.why, "after": fix.after,
                      "every_way": fix.every_way, "ways": [{"heading": way.heading, "steps": list(way.steps), "in_dm": way.in_dm} for way in ways]})
    return fixes


def page(reason: str) -> dict | None:
    """Every way for one check, for its help page."""
    fix = FIXES.get(reason)
    if fix is None:
        return None
    return {"title": fix.title, "why": fix.why, "ways": [{"heading": way.heading, "title": way.title, "why": way.why, "steps": list(way.steps)} for way in fix.ways]}


def strings() -> list[str]:
    """Every string a member can see, for the translations."""
    found = []
    for fix in FIXES.values():
        found += [fix.title, fix.why]
        for way in fix.ways:
            found += [way.heading, *way.steps] + [text for text in (way.title, way.why) if text]
    return list(dict.fromkeys(found))


__all__ = ["FIXES", "Fix", "Way", "for_findings", "ordered_ways", "page", "strings"]

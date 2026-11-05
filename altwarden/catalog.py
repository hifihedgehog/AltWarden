"""The checks AltWarden can run, the actions it can take, and the presets that set them.

The dashboard and the engine both read this table, so a check exists in exactly one place.
"""
from __future__ import annotations

from dataclasses import dataclass

# What happens when a check fails. "watch" records the result and lets the member in, so staff
# can see what a rule would catch before it blocks anyone.
WATCH, DENY, KICK, BAN = "watch", "deny", "kick", "ban"
ACTIONS = (WATCH, DENY, KICK, BAN)
SEVERITY = {WATCH: 0, DENY: 1, KICK: 2, BAN: 3}
HONEYPOT_ACTIONS = ("log", "timeout", "kick", "softban", "ban")

WEB, BUTTON, INSTANT = "web", "button", "instant"
MODES = (WEB, BUTTON, INSTANT)
ALL_MODES = frozenset(MODES)
WEB_ONLY = frozenset({WEB})

GROUPS = {
    "account": ("Account", "The Discord account behind each member."),
    "network": ("Network", "Where the member is really connecting from."),
    "browser": ("Browser", "Browsers that hide, fake or automate."),
    "device": ("Device", "The machine behind the verification."),
}


@dataclass(frozen=True)
class Check:
    id: str
    group: str
    name: str
    blurb: str
    modes: frozenset
    needs: tuple = ()  # Discord permissions beyond the action's own

    @property
    def web_only(self) -> bool:
        return self.modes == WEB_ONLY


CHECKS: tuple[Check, ...] = (
    Check("max_attempts", "account", "Attempt limit", "Stops members after too many failed tries.", ALL_MODES),
    Check("account_age", "account", "Account age", "Turns away accounts younger than a set age.", ALL_MODES),
    Check("avatar", "account", "Profile picture", "Requires a profile picture.", ALL_MODES),
    Check("mfa", "account", "Two-factor login", "Requires two-factor login on the Discord account.", WEB_ONLY),
    Check("disposable_email", "account", "Throwaway email", "Rejects accounts with no verified email or a throwaway inbox. The address is checked, then discarded.", WEB_ONLY),
    Check("alt_account", "account", "Alt accounts", "Finds a second account of someone who verified here or was banned here.", WEB_ONLY),
    Check("vpn", "network", "VPN and proxy", "Catches connections through a VPN, proxy, Tor, iCloud Private Relay or a data center.", WEB_ONLY),
    Check("mobile_data", "network", "Mobile data", "Catches connections on a mobile carrier network.", WEB_ONLY),
    Check("geogate", "network", "Country rules", "Allows or blocks verification by country.", WEB_ONLY),
    Check("automation", "browser", "Automated browser", "Catches browsers driven by a script.", WEB_ONLY),
    Check("antidetect", "browser", "Anti-detect browser", "Catches browsers that invent a new device per profile.", WEB_ONLY),
    Check("tampering", "browser", "Browser tampering", "Catches browsers whose built-in functions were rewritten.", WEB_ONLY),
    Check("fake_ua", "browser", "Fake browser identity", "Catches a browser claiming to be a different browser or system.", WEB_ONLY),
    Check("devtools", "browser", "Developer tools", "Catches developer tools open during verification.", WEB_ONLY),
    Check("incognito", "browser", "Private window", "Catches a private or incognito window.", WEB_ONLY),
    Check("privacy", "browser", "Fingerprint blocking", "Catches browsers that randomize or hide device details.", WEB_ONLY),
    Check("threat", "browser", "Threat score", "Adds up many small signals into two scores, and acts when either reaches its limit.", WEB_ONLY),
    Check("vm", "device", "Virtual machine", "Catches a virtual machine or software graphics.", WEB_ONLY),
    Check("rooted", "device", "Modified phone", "Catches emulators, and Pixel phones whose model doesn't fit their hardware or whose firmware is newer than that model ever got.", WEB_ONLY),
)
CHECK_IDS = tuple(check.id for check in CHECKS)
BY_ID = {check.id: check for check in CHECKS}

# Log modules beyond the one each check gets.
EXTRA_LOG_MODULES = {
    "general": "Staff actions",
    "success": "Verified members",
    "auto_kick": "Auto kick",
    "help_desk": "Help desk",
    "honeypot": "Honeypot",
    "raid": "Raid alerts",
    "appeals": "Appeals",
    "settings": "Settings changes",
}
LOG_MODULES = tuple(EXTRA_LOG_MODULES) + CHECK_IDS

# Each preset sets every check it lists, with every option, so the result never depends on the preset
# before it. A row that's off still stores Deny, so switching it on later starts at Deny. Two-factor login,
# country rules, roles, channels and messages aren't listed, so they survive a change. "core" is what every
# preset sets among the core settings. "auto_kick" switches the Auto Kick timer on or off, and only a preset
# that turns it on also sets its minutes.
ALL_METHODS = {"cookie": True, "fingerprint": True, "ip": True}
PRESET_CORE = {"auto_dm": True, "notify_closed_dms": {"enabled": True, "seconds": 30}}
PRESETS: dict[str, dict] = {
    "gentle": {
        "label": "Gentle",
        "blurb": "Stops throwaway emails, fake browser identities and alt accounts. Everything else stays off. Two-factor login keeps its own setting.",
        "auto_kick": False,
        "core": PRESET_CORE,
        "checks": {
            "account_age": (False, DENY, {"days": 7}),
            "avatar": (False, DENY, {}),
            "disposable_email": (True, DENY, {}),
            "alt_account": (True, DENY, {"alt_action": DENY, "main_action": WATCH, "banned_alt_action": DENY, "min_confidence": "likely", "methods": ALL_METHODS}),
            "max_attempts": (False, DENY, {"attempts": 5, "reset_minutes": 1440}),
            "vpn": (False, DENY, {}),
            "mobile_data": (False, DENY, {}),
            "automation": (False, DENY, {}),
            "antidetect": (False, DENY, {}),
            "tampering": (False, DENY, {"anomaly_score": 50}),
            "fake_ua": (True, DENY, {}),
            "devtools": (False, DENY, {}),
            "incognito": (False, DENY, {}),
            "privacy": (False, DENY, {}),
            "threat": (False, DENY, {"bot_score": 80, "suspect_score": 70}),
            "vm": (False, DENY, {}),
            "rooted": (False, DENY, {}),
        },
    },
    "standard": {
        "label": "Standard",
        "blurb": "Stops anyone who fails a check. Kicks fake browser identities, and alt accounts proven by the browser cookie.",
        "auto_kick": False,
        "core": PRESET_CORE,
        "checks": {
            "account_age": (True, DENY, {"days": 7}),
            "avatar": (False, DENY, {}),
            "disposable_email": (True, DENY, {}),
            "alt_account": (True, KICK, {"alt_action": KICK, "main_action": WATCH, "banned_alt_action": BAN, "min_confidence": "likely", "methods": ALL_METHODS}),
            "max_attempts": (True, DENY, {"attempts": 5, "reset_minutes": 1440}),
            "vpn": (True, DENY, {}),
            "mobile_data": (False, DENY, {}),
            "automation": (True, DENY, {}),
            "antidetect": (True, DENY, {}),
            "tampering": (True, DENY, {"anomaly_score": 50}),
            "fake_ua": (True, KICK, {}),
            "devtools": (True, DENY, {}),
            "incognito": (True, DENY, {}),
            "privacy": (True, DENY, {}),
            "threat": (True, DENY, {"bot_score": 80, "suspect_score": 70}),
            "vm": (True, DENY, {}),
            "rooted": (True, DENY, {}),
        },
    },
    "strict": {
        "label": "Strict",
        "blurb": "For servers under attack. Kicks or bans on most failures, and removes anyone who doesn't verify within 10 minutes.",
        "auto_kick": True,
        "auto_kick_minutes": 10,
        "core": PRESET_CORE,
        "checks": {
            "account_age": (True, KICK, {"days": 30}),
            "avatar": (True, KICK, {}),
            "disposable_email": (True, KICK, {}),
            "alt_account": (True, BAN, {"alt_action": BAN, "main_action": KICK, "banned_alt_action": BAN, "min_confidence": "likely", "methods": ALL_METHODS}),
            "max_attempts": (True, KICK, {"attempts": 3, "reset_minutes": 0}),
            "vpn": (True, KICK, {}),
            "mobile_data": (True, DENY, {}),
            "automation": (True, KICK, {}),
            "antidetect": (True, KICK, {}),
            "tampering": (True, KICK, {"anomaly_score": 40}),
            "fake_ua": (True, KICK, {}),
            "devtools": (True, DENY, {}),
            "incognito": (True, KICK, {}),
            "privacy": (True, DENY, {}),
            "threat": (True, KICK, {"bot_score": 70, "suspect_score": 50}),
            "vm": (True, KICK, {}),
            "rooted": (True, KICK, {}),
        },
    },
}
DEFAULT_PRESET = "standard"

# Why a failed check sends a member away. Written for the member, with what to do next where they can do something.
FAILURE_TEXT = {
    "max_attempts": "You have used all your verification attempts for this server.",
    "cooldown": "Please wait before trying again.",
    "account_age": "This server only accepts Discord accounts older than {days} days.",
    "account_age_one": "This server only accepts Discord accounts older than 1 day.",
    "avatar": "This server requires a profile picture. Set one in Discord, then try again.",
    "mfa": "This server requires two-factor login on your Discord account.",
    "no_email": "Your Discord account has no verified email address.",
    "disposable_email": "Your Discord account uses a throwaway email address.",
    "alt_account": "This account looks linked to another account in this server.",
    "vpn": "Your connection looks like a VPN or proxy. Turn it off and try again.",
    "mobile_data": "This server doesn't accept mobile data connections. Try Wi-Fi.",
    "geogate": "This server doesn't accept verification from your country.",
    "automation": "Your browser looks automated. Open the link in a normal browser.",
    "antidetect": "Your browser is hiding what device it's on. Turn off extensions that change this, or use a normal browser.",
    "tampering": "Your browser's built-in functions look modified. Turn off extensions that change them.",
    "fake_ua": "Your browser is reporting a different browser or system than it is. Turn off user agent switchers and try again.",
    "devtools": "Close your browser's developer tools and try again.",
    "incognito": "Open the link in a normal window, not a private one.",
    "privacy": "Your browser is blocking the details this server needs. Turn off fingerprint protection or Brave Shields for this site, or use a browser with default settings.",
    "threat": "This attempt scored too high on risk. Try another browser or connection.",
    "vm": "Open the link on your own device, not inside a virtual machine. If this is your own computer, turn on hardware acceleration in your browser or update your graphics driver.",
    "rooted": "This server doesn't accept emulated or modified phones. Use a regular device.",
}

# Where each failure's help page lives on the site.
HELP_SLUG = {check_id: check_id.replace("_", "-") for check_id in FAILURE_TEXT}
HELP_SLUG["account_age_one"] = HELP_SLUG["account_age"]

# Each permission by the name Discord's own settings show.
PERMISSION_LABELS = {
    "administrator": "Administrator", "manage_guild": "Manage Server", "manage_roles": "Manage Roles", "manage_channels": "Manage Channels",
    "manage_messages": "Manage Messages", "manage_nicknames": "Manage Nicknames", "moderate_members": "Timeout Members", "kick_members": "Kick Members",
    "ban_members": "Ban Members", "view_audit_log": "View Audit Log", "view_channel": "View Channel", "send_messages": "Send Messages",
    "embed_links": "Embed Links", "read_message_history": "Read Message History", "mention_everyone": "Mention @everyone, @here and All Roles",
    "change_nickname": "Change Nickname", "manage_threads": "Manage Threads", "create_private_threads": "Create Private Threads",
    "send_messages_in_threads": "Send Messages in Threads", "pin_messages": "Pin Messages",
    "create_instant_invite": "Create Invite", "external_emojis": "Use External Emoji",
}

ACTION_LABEL = {WATCH: "Watch", DENY: "Deny", KICK: "Kick", BAN: "Ban"}
ACTION_BLURB = {
    WATCH: "Record it and let them in.",
    DENY: "Don't verify them. They can try again.",
    KICK: "Tell them they didn't pass, then kick them.",
    BAN: "Tell them they didn't pass, then ban them.",
}

<p align="center">
  <img src="assets/header.png" alt="AltWarden: Discord verification with no readable IPs or emails" width="100%">
</p>

<p align="center">
  <a href="https://github.com/hifihedgehog/AltWarden/actions/workflows/tests.yml"><img src="https://github.com/hifihedgehog/AltWarden/actions/workflows/tests.yml/badge.svg?branch=main" alt="Tests"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/hifihedgehog/AltWarden?color=14b8a6" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-1f2a44" alt="Python 3.11, 3.12, 3.13">
  <img src="https://img.shields.io/badge/discord.py-2.7.1-5865f2" alt="discord.py 2.7.1">
</p>

AltWarden is a self-hosted Discord verification bot with a web dashboard. It checks new members for alt accounts, ban evasion, VPNs and raids, and it stores no readable IP addresses, emails, cookies, fingerprints or Discord tokens.

In October 2026 the verification bot Double Counter said an attacker may have reached records on about 28 million Discord accounts, including about 27 million IP addresses. [Have I Been Pwned](https://haveibeenpwned.com/Breach/DoubleCounter) lists about 275,000 email addresses from the leak. Verification bots collect that data because they need it for a moment. AltWarden uses it for that moment and keeps a keyed hash instead, under a separate key for every server.

## What a stolen database would give an attacker

An encrypted file. The database, its write-ahead log and its nightly backups are encrypted with [SQLCipher](https://github.com/sqlcipher/sqlcipher), under a key derived from `MASTER_KEY` that's never stored. Without the master key, no table, name or row can be read from any of them.

Even with the key, this is all the file holds:

| In the database | Not in the database |
|---|---|
| Discord IDs, usernames and avatars of people who tried to verify | Any IP address, email address, cookie value or fingerprint |
| Attempt results and labels | Any Discord access or refresh token |
| Keyed hashes they can't read without the key | A way to connect one person's hashes across two servers |
| Webhook addresses and secrets, and any proxycheck.io key, encrypted | Any of those in readable form, without the master key |

The [security page](altwarden/web/static/security.html) lists how that works.

## At a glance

| | |
|---|---|
| Source code | Public, MIT |
| Database at rest | Encrypted, with its log and backups |
| Raw IPs and fingerprints at rest | None |
| Discord tokens at rest | None |
| Ads on the verification page | None |
| Outside scripts on the verification page | None |
| Works with an ad blocker on | Yes |
| Forced wait on the verification page | None |
| Default for a new server | The Standard preset, which stops people |
| A rule that records without blocking | The Watch action, if you set it |
| Alt matching | Weighs evidence, and shows staff how strong a match is |
| Alt matches | Any one match on connection, browser cookie or fingerprint, and your chosen action applies |
| Alts of banned accounts | Their own action |
| Raid mode | Automatic, from the join rate |
| When a member fails | Every check that stopped them, each with steps for their own device and browser, on the page and by DM |
| Appeals | From the result page, decided with buttons in Discord |
| Settings changes | Logged with before and after values |
| Data deletion | Self-service |
| Administrator | Asked for by default |
| Who can add it | Only you, while Public Bot is off |
| Webhooks and API | Signed webhooks, and read-only API keys |
| Languages for members | English, German, Spanish, French, Japanese, Korean, Portuguese, Russian, Chinese |

## What it checks

| Group | Checks |
|---|---|
| Account | Account age, profile picture, two-factor login, throwaway email, alt accounts, attempt limit |
| Network | VPN, proxy, Tor, Apple Private Relay, data centers, mobile data, country rules |
| Browser | Automation, anti-detect browsers, tampering, fake identity, developer tools, private windows, fingerprint blocking, bot and suspect scores |
| Device | Virtual machines, Android emulators, and Pixel phones whose model doesn't fit their graphics chip or whose Android is newer than that model ever got |

Each check can Watch, Deny, Kick or Ban. Every enabled check runs on an attempt, and the strongest action wins. A running cooldown or a used-up Deny limit ends the attempt first.

Browser checks use published open-source work, served from your own site: [FingerprintJS](https://github.com/fingerprintjs/fingerprintjs), [BotD](https://github.com/fingerprintjs/BotD) and [detectIncognito](https://github.com/Joe12387/detectIncognito). The tamper checks follow [CreepJS](https://github.com/abrahamjuliot/creepjs). Network data comes from [open lists](THIRD_PARTY.md), searched in memory, so no address leaves your server unless a server's staff turn on the optional outside lookup. A failed lookup stops nobody.

## Staff tools

Logs per check, role alerts, a help desk with private threads, appeals, bypass links, a honeypot channel, per-page and per-command access rules, Discord's own command permissions, analytics, a health report that works out the smallest permissions your settings need, and an audit log. Each server can set AltWarden's picture, name, bio, and name font and effect there.

The name style fields come from [Discord Userdoccers](https://github.com/discord-userdoccers/discord-userdoccers). If Discord refuses a style, the page says so and the rest still saves.

## Host it yourself

You need Python 3.11 or newer and a reverse proxy with HTTPS.

1. Create an application in the [Discord Developer Portal](https://discord.com/developers/applications). Turn on **Server Members Intent**, and leave Presence and Message Content off. Turn off **Public Bot**, so only you can add it to a server. Add these OAuth2 redirects, with your own address:
   ```
   https://your.site/verify/callback
   https://your.site/dashboard/callback
   ```
2. Install it:
   ```sh
   git clone https://github.com/hifihedgehog/AltWarden.git
   cd AltWarden
   python -m venv venv && . venv/bin/activate
   pip install -r requirements.txt
   python -m altwarden.keygen
   cp .env.example .env
   chmod 600 .env
   ```
   Put the printed key in `.env` as `MASTER_KEY`, with your bot token and client secret. Back up the key on its own, away from the database. The database and its backups open only with this key.
3. Run it:
   ```sh
   python -m altwarden --public-url https://your.site --port 8892
   ```
   It creates an encrypted database on the first run, listens on `127.0.0.1` and downloads its network lists. Its log has the link for adding the bot to your server. `altwarden.service` is a hardened systemd unit.
4. Point your proxy at that port, have it add the client address as the last value of `X-Forwarded-For`, which is the only value AltWarden reads, and **turn off the proxy's access log or remove the client address from it**. Otherwise raw addresses end up in your web logs. If no usable address arrives, verification answers 503. If you keep database backups, say how long on your privacy page.

To copy the database while the bot runs, use `python -m altwarden.backup data/altwarden.db backups/altwarden.db`. The copy is encrypted under the same key.

If you ran a version before 1.3, convert your database once. Stop the bot, then run:

```sh
python -m altwarden.encrypt_database data/altwarden.db data/altwarden-encrypted.db
```

It checks every table against the original before it finishes. Move the new file over `data/altwarden.db`, start the bot, and encrypt or remove any older plain copies.

### Getting the data back

Everything comes back with `MASTER_KEY`, so keep a copy of it somewhere safe.

To put a copy back, stop the bot, delete `altwarden.db-wal` and `altwarden.db-shm` if they're there, copy the backup over `data/altwarden.db`, and start the bot.

To read the data in any SQLite tool, make a plain copy:

```sh
python -m altwarden.decrypt_database backups/altwarden.db readable.db
```

It checks every table against the source before it finishes. The new file isn't encrypted, so keep it private and delete it when you're done.

Run the tests with `python -m unittest discover -s tests`. `python scripts/browser_check.py` drives the real pages in headless Edge or Chrome, and changes every control on the Rules, Messages and Access pages to prove it saves. `python scripts/detector_controls.py` and `python scripts/engine_controls.py` run the browser checks on real Chromium, Firefox and WebKit, clean and with what each check should catch.

## Commands

`/setup`, `/settings`, `/post-message`, `/health`, `/verify-user`, `/reset-user`, `/create-bypass`, `/lookup`, `/trust-accounts`, `/import-members`, `/raid`, `/uninstall`, `/my-data`, `/help` and `/ping`. Right-click a member for Verify, Reset, Create Bypass and Lookup. The [docs page](altwarden/web/static/docs.html) covers each one and who can run it.

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY.md](THIRD_PARTY.md).

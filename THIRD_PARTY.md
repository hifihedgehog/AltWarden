# Third-party work

## Shipped with AltWarden

| Component | Version | License | File |
|---|---|---|---|
| [FingerprintJS](https://github.com/fingerprintjs/fingerprintjs) | 5.3.0 | MIT | `altwarden/web/static/vendor/a-5.3.0.min.js` |
| [BotD](https://github.com/fingerprintjs/BotD) | 2.0.0 | MIT | `altwarden/web/static/vendor/b-2.0.0.esm.js` |
| [detectIncognito](https://github.com/Joe12387/detectIncognito) | 1.9.0 | MIT | `altwarden/web/static/vendor/c-1.9.0.min.js` |
| [world-atlas](https://github.com/topojson/world-atlas), from Natural Earth | 2.0.2 | ISC, public domain data | `altwarden/web/static/world.json` |
| [ISO-3166 countries with regional codes](https://github.com/lukes/ISO-3166-Countries-with-Regional-Codes) | commit 99cdae1 | CC BY-SA 4.0 | `altwarden/web/static/countries.json`, cut down to five fields, with Kosovo added and blank regions filled in |
| Cherry Bomb One, Chicle, MuseoModerno, Pixelify Sans, Zilla Slab, Playpen Sans, Orbitron, New Rocker, Kalam, from [Google Fonts](https://fonts.google.com) | Latin subset | SIL OFL 1.1 | `altwarden/web/static/vendor/fonts/`, with `OFL.txt` |

The three browser libraries carry short file names so that filter lists don't block them by name. Each file's header names its project and version.

## Python packages

Pinned in `requirements.lock`, and not part of this repository.

| Package | Version | License |
|---|---|---|
| [discord.py](https://github.com/Rapptz/discord.py) | 2.7.1 | MIT |
| [aiohttp](https://github.com/aio-libs/aiohttp) | 3.14.5 | Apache 2.0 and MIT |
| [aiosqlite](https://github.com/omnilib/aiosqlite) | 0.22.1 | MIT |
| [cryptography](https://github.com/pyca/cryptography) | 50.0.0 | Apache 2.0 or BSD 3-Clause |
| [python-dotenv](https://github.com/theskumar/python-dotenv) | 1.2.4 | BSD 3-Clause |
| [yarl](https://github.com/aio-libs/yarl) | 1.25.1 | Apache 2.0 |
| [aiohappyeyeballs](https://github.com/aio-libs/aiohappyeyeballs) | 2.7.1 | PSF 2.0 |
| [aiosignal](https://github.com/aio-libs/aiosignal) | 1.4.0 | Apache 2.0 |
| [attrs](https://github.com/python-attrs/attrs) | 26.1.0 | MIT |
| [audioop-lts](https://github.com/AbstractUmbra/audioop) | 0.2.2 | PSF 2.0 |
| [cffi](https://github.com/python-cffi/cffi) | 2.1.1 | MIT-0 |
| [frozenlist](https://github.com/aio-libs/frozenlist) | 1.8.0 | Apache 2.0 |
| [idna](https://github.com/kjd/idna) | 3.20 | BSD 3-Clause |
| [multidict](https://github.com/aio-libs/multidict) | 7.2.1 | Apache 2.0 |
| [propcache](https://github.com/aio-libs/propcache) | 0.5.4 | Apache 2.0 |
| [pycparser](https://github.com/eliben/pycparser) | 3.12 | BSD 3-Clause |

## Methods followed

| Project | License | Used for |
|---|---|---|
| [CreepJS](https://github.com/abrahamjuliot/creepjs) | MIT | Native function tests, the rule for a removed webdriver flag, worker scope comparison, privacy browser detection, virtual GPU names |
| [devtools-detector](https://github.com/AEPKILL/devtools-detector) | MIT | Console timing test |
| [ALTCHA](https://github.com/altcha-org/altcha) | MIT | Proof-of-work design |
| [FileSaver.js](https://github.com/eligrey/FileSaver.js) | MIT | How long a download's address stays open |
| [Discord Userdoccers](https://github.com/discord-userdoccers/discord-userdoccers) | CC BY-SA 4.0 | Name style fields, font and effect IDs |
| [brave-core](https://github.com/brave/brave-core) | MPL 2.0 | Read for how Brave's Shields change a browser's plugin list. No code came from it. |
| [Bot-NameStyles](https://github.com/itsfizys/Bot-NameStyles), [discord-bot-namestyles](https://github.com/mwyeow/discord-bot-namestyles), [Display-Name-effect](https://github.com/dray-me/Display-Name-effect), [GlowForNodejs](https://github.com/kyronixstudio/GlowForNodejs) | None stated, or all rights reserved | Read for facts about Discord's API: color counts, clearing a style, checking that Discord applied it. No code or text came from them. |

## Downloaded at runtime

These lists are fetched by each installation and aren't part of this repository.

| List | License |
|---|---|
| [ip-location-db](https://github.com/sapics/ip-location-db) `user-country`, `origin-asn` | PDDL 1.0 |
| [X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn) | MIT for its scripts and generated lists. Its default build starts from the IPLocate database, which is CC BY-SA 4.0. See `ASN-DATABASE.txt` in that project. |
| [open-source-vpn-ip-lists](https://github.com/Joe12387/open-source-vpn-ip-lists) | CC0 |
| [disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) | CC0 |
| [Tor bulk exit list](https://check.torproject.org/torbulkexitlist) | Published by the Tor Project |
| [Apple Private Relay egress ranges](https://mask-api.icloud.com/egress-ip-ranges.csv) | Published by Apple |

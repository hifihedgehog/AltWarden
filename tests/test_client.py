"""The real slash commands, buttons and posting code, driven with a stand-in for Discord's interaction object."""
import json
import os
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import discord

from altwarden import settings
from altwarden.bot.client import AltWardenBot, BypassView, intents, result_embed
from altwarden.ports import MemberInfo
from altwarden.service import Result
from fakes import CHANNEL, GUILD, LOG_CHANNEL, OLD_USER, OTHER_USER, STAFF, VERIFIED_ROLE
from test_flow import Base

STAFF_ROLE = "970000000000000070"


class Rank:
    """Compares like a discord.Role does, by position."""

    def __init__(self, position, role_id=VERIFIED_ROLE, default=False, managed=False):
        self.position, self.id, self.default, self.managed = position, int(role_id), default, managed
        self.mention = f"<@&{role_id}>"

    def __ge__(self, other):
        return self.position >= other.position

    def is_default(self):
        return self.default


def fake_interaction(user_id=STAFF, *, perms=("manage_guild", "manage_roles"), owner=False, top=9, bot_top=20):
    user = SimpleNamespace(id=int(user_id), name="staff", top_role=Rank(top), mention=f"<@{user_id}>", bot=False, perms=perms, owner=owner)
    interaction = MagicMock()
    interaction.user = user
    interaction.guild_id = int(GUILD)
    interaction.channel_id = int(CHANNEL)
    interaction.guild.me.top_role = Rank(bot_top)
    state = {"done": False}

    async def respond(*args, **kwargs):
        state["done"] = True
        interaction.said.append((args[0] if args else "", kwargs))

    async def defer(**kwargs):
        state["done"] = True

    async def follow(*args, **kwargs):
        interaction.said.append((args[0] if args else "", kwargs))

    interaction.said = []
    interaction.response.send_message = AsyncMock(side_effect=respond)
    interaction.response.defer = AsyncMock(side_effect=defer)
    interaction.response.is_done = lambda: state["done"]
    interaction.followup.send = AsyncMock(side_effect=follow)
    interaction.edit_original_response = AsyncMock(side_effect=lambda **kwargs: interaction.said.append((kwargs.get("content", ""), kwargs)))
    return interaction


def said(interaction) -> str:
    return " | ".join(str(text) for text, _ in interaction.said)


class Client(Base):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.bot = AltWardenBot()
        self.bot.service = self.service
        self.bot.gateway = self.port
        # Staff rank above the members they act on, unless a test says otherwise, since commands now ask.
        self.port.extra_roles = [{"id": STAFF_ROLE, "name": "Staff", "color": 0, "position": 4, "managed": False, "mentionable": False}]
        self.port.info = lambda user: MemberInfo(GUILD, str(user.id), user.name, None, False, getattr(user, "role_ids", (STAFF_ROLE,)), frozenset(user.perms), user.owner)

    async def asyncTearDown(self):
        await self.bot.close()
        await super().asyncTearDown()

    def command(self, name):
        return self.bot.tree.get_command(name).callback

    async def forget_setup(self):
        await self.db.run("UPDATE guilds SET setup_done = 0")


class CommandList(Client):
    """What's sent to Discord decides who sees a command in its list."""

    def sent(self):
        return {command.name: command.to_dict(self.bot.tree) for command in self.bot.tree.get_commands()}

    async def test_staff_commands_ask_for_the_permission_their_rule_needs(self):
        administrator, kick_members, manage_guild, manage_roles = 1 << 3, 1 << 1, 1 << 5, 1 << 28
        sent = self.sent()
        for name in ("verify-user", "reset-user", "create-bypass", "trust-accounts", "lookup", "Verify", "Reset", "Create Bypass", "Lookup"):
            self.assertEqual(sent[name]["default_member_permissions"], manage_roles, name)
        for name in ("setup", "settings", "post-message", "health"):
            self.assertEqual(sent[name]["default_member_permissions"], manage_guild, name)
        self.assertEqual(sent["uninstall"]["default_member_permissions"], administrator)
        self.assertEqual(sent["raid"]["default_member_permissions"], manage_guild | kick_members)
        self.assertEqual(sent["import-members"]["default_member_permissions"], manage_guild | manage_roles)

    async def test_member_commands_stay_listed_for_everyone(self):
        sent = self.sent()
        for name in ("help", "ping", "my-data"):
            self.assertIsNone(sent[name]["default_member_permissions"], name)

    async def test_no_staff_command_is_missed(self):
        """A renamed command or rule would otherwise stay in every member's list without anyone noticing."""
        sent = self.sent()
        self.assertEqual(len(sent), 19)
        listed_for_all = {name for name, body in sent.items() if body["default_member_permissions"] is None}
        self.assertEqual(listed_for_all, {"help", "ping", "my-data"})


class SetupCommand(Client):
    async def run(self, interaction, role=None):
        role = role or Rank(2)
        channel = SimpleNamespace(id=int(CHANNEL), mention=f"<#{CHANNEL}>")
        await self.command("setup")(interaction, role, channel)

    async def test_only_works_before_setup(self):
        interaction = fake_interaction()
        await self.run(interaction)
        self.assertIn("already set up", said(interaction))

    async def test_refuses_a_role_above_your_own(self):
        await self.forget_setup()
        interaction = fake_interaction(top=1)
        await self.run(interaction)
        self.assertIn("below your own", said(interaction))
        self.assertFalse(await self.service.is_set_up(GUILD))

    async def test_administrators_skip_that_rule(self):
        await self.forget_setup()
        self.bot.post_message = AsyncMock(return_value=True)
        interaction = fake_interaction(top=1, perms=("administrator",))
        await self.run(interaction)
        self.assertTrue(await self.service.is_set_up(GUILD))
        self.bot.post_message.assert_awaited_once()

    async def test_refuses_a_role_above_the_bot(self):
        await self.forget_setup()
        interaction = fake_interaction(perms=("administrator",), bot_top=1)
        await self.run(interaction)
        self.assertIn("Drag AltWarden", said(interaction))

    async def test_refuses_everyone_and_managed_roles(self):
        await self.forget_setup()
        for role in (Rank(0, default=True), Rank(2, managed=True)):
            interaction = fake_interaction(perms=("administrator",))
            await self.run(interaction, role)
            self.assertIn("regular role", said(interaction))

    async def test_a_member_without_manage_server_is_turned_away(self):
        await self.forget_setup()
        interaction = fake_interaction(perms=())
        await self.run(interaction)
        self.assertIn("don't have access", said(interaction))


class StaffCommands(Client):
    def target(self, user_id=OLD_USER, *, bot=False):
        return SimpleNamespace(id=int(user_id), mention=f"<@{user_id}>", bot=bot, name="someone")

    async def test_commands_wait_for_setup(self):
        await self.forget_setup()
        for name in ("verify-user", "reset-user", "create-bypass"):
            interaction = fake_interaction()
            await self.command(name)(interaction, self.target())
            self.assertIn("isn't set up", said(interaction), name)

    async def test_verify_user(self):
        interaction = fake_interaction()
        await self.command("verify-user")(interaction, self.target())
        self.assertIn("is verified", said(interaction))
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["method"], "staff")

    async def test_verify_user_explains_a_role_failure(self):
        self.port.role_problem = "That role no longer exists."
        interaction = fake_interaction()
        await self.command("verify-user")(interaction, self.target())
        self.assertIn("no longer exists", said(interaction))

    async def test_bots_are_refused(self):
        interaction = fake_interaction()
        await self.command("verify-user")(interaction, self.target(bot=True))
        self.assertIn("Bots don't verify", said(interaction))
        interaction = fake_interaction()
        await self.command("create-bypass")(interaction, self.target(bot=True))
        self.assertIn("for a bot", said(interaction))

    async def test_reset_reply_says_whether_they_were_told(self):
        interaction = fake_interaction()
        await self.command("reset-user")(interaction, self.target())
        self.assertIn("They were told", said(interaction))
        self.port.dm_open = False
        self.port.channel_posts_work = False
        interaction = fake_interaction()
        await self.command("reset-user")(interaction, self.target())
        self.assertIn("They weren't told", said(interaction))

    async def test_bypass_refusals(self):
        interaction = fake_interaction()
        await self.command("create-bypass")(interaction, self.target(OTHER_USER))
        self.assertIn("isn't in the server", said(interaction))
        self.port.members[(GUILD, OLD_USER)].role_ids = (VERIFIED_ROLE,)
        interaction = fake_interaction()
        await self.command("create-bypass")(interaction, self.target())
        self.assertIn("already verified", said(interaction))

    async def test_bypass_with_nothing_to_skip(self):
        document = await self.service.get_settings(GUILD)
        for check in document["checks"].values():
            check["enabled"] = False
        await self.service.save_settings(GUILD, document)
        interaction = fake_interaction()
        await self.command("create-bypass")(interaction, self.target())
        self.assertIn("nothing to skip", said(interaction))

    async def test_bypass_window_offers_every_choice(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        interaction = fake_interaction()
        await self.command("create-bypass")(interaction, self.target())
        view = interaction.said[0][1]["view"]
        self.assertIsInstance(view, BypassView)
        self.assertIn("vpn", [option.value for option in view.checks.options])
        self.assertEqual([option.value for option in view.tell.options], ["both", "dm", "channel", "none"])
        self.assertEqual([option.value for option in view.lasts.options], ["1", "6", "12", "24", "48", "72", "168"])
        self.assertEqual(next(option.value for option in view.tell.options if option.default), "both")

    async def press_create(self, view, interaction):
        await view.create.callback(interaction)

    async def test_staff_always_get_the_link(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        for notify in ("both", "dm", "channel", "none"):
            view = BypassView(self.bot, self.target(), ["vpn"], 2, notify)
            view.choice = ["vpn"]
            interaction = fake_interaction()
            await self.press_create(view, interaction)
            self.assertIn("/v/", said(interaction), notify)
            self.assertEqual(interaction.said[0][1]["ephemeral"], True, "only staff may see the link")

    async def test_a_silent_link_tells_staff_to_send_it(self):
        view = BypassView(self.bot, self.target(), ["vpn"], 1, "none")
        view.choice = ["vpn"]
        interaction = fake_interaction()
        await self.press_create(view, interaction)
        self.assertIn("send it to them yourself", said(interaction))

    async def test_create_needs_a_check(self):
        view = BypassView(self.bot, self.target(), ["vpn"], 1, "dm")
        interaction = fake_interaction()
        await self.press_create(view, interaction)
        self.assertIn("Pick at least one", said(interaction))

    async def test_lookup_stays_inside_discords_limit(self):
        for index in range(60):
            await self.db.run("INSERT INTO links VALUES (?, ?, ?, ?, ?, ?, ?)", (GUILD, OLD_USER, str(175928847299200000 + index), "likely", 70, "[]", time.time()))
        await self.db.touch_member(GUILD, OLD_USER)
        interaction = fake_interaction()
        await self.command("lookup")(interaction, self.target())
        self.assertLess(len(said(interaction)), 2000)


class EverydayCommands(Client):
    async def test_settings_reply_is_public(self):
        interaction = fake_interaction()
        await self.command("settings")(interaction)
        kwargs = interaction.said[0][1]
        self.assertFalse(kwargs.get("ephemeral", False))
        self.assertIn("Standard", kwargs["embed"].description)

    async def test_help_has_a_way_to_get_support(self):
        interaction = fake_interaction()
        await self.command("help")(interaction)
        self.assertIn("/docs", said(interaction))
        self.assertIn("github.com", said(interaction))

    async def test_post_message_says_when_it_failed(self):
        self.bot.post_message = AsyncMock(return_value=False)
        interaction = fake_interaction()
        await self.command("post-message")(interaction, SimpleNamespace(value="verification"))
        self.assertIn("Couldn't post", said(interaction))

    async def test_uninstall_asks_first_and_cancel_changes_nothing(self):
        interaction = fake_interaction(perms=("administrator",))
        await self.command("uninstall")(interaction)
        view = interaction.said[0][1]["view"]
        self.assertEqual(view.timeout, 60)
        await view.cancel.callback(fake_interaction())
        self.assertTrue(await self.service.is_set_up(GUILD))

    async def test_uninstall_removes_the_posts_and_every_record(self):
        await self.db.set_guild_field(GUILD, "verify_message_id", f"{CHANNEL}:555")
        await self.db.touch_member(GUILD, OLD_USER)
        interaction = fake_interaction(perms=("administrator",))
        await self.command("uninstall")(interaction)
        await interaction.said[0][1]["view"].confirm.callback(fake_interaction(perms=("administrator",)))
        self.assertIn(("delete_message", CHANNEL, "555"), self.port.calls)
        self.assertIsNone(await self.db.guild(GUILD))
        self.assertIsNone(await self.db.member(GUILD, OLD_USER))

    def test_message_text_is_not_requested(self):
        self.assertFalse(intents().message_content)
        self.assertFalse(intents().presences)


class Posting(Client):
    async def test_a_new_post_replaces_the_old_one_in_its_old_channel(self):
        await self.db.set_guild_field(GUILD, "verify_message_id", f"{LOG_CHANNEL}:555")
        self.assertTrue(await self.bot.post_message(GUILD, "verification"))
        self.assertIn(("delete_message", LOG_CHANNEL, "555"), self.port.calls)
        row = await self.db.guild(GUILD)
        self.assertTrue(row["verify_message_id"].startswith(f"{CHANNEL}:"))

    async def test_a_failed_post_leaves_the_old_one_up(self):
        await self.db.set_guild_field(GUILD, "verify_message_id", f"{CHANNEL}:555")
        self.port.channel_posts_work = False
        self.assertFalse(await self.bot.post_message(GUILD, "verification"))
        self.assertFalse(self.port.did("delete_message"))
        self.assertEqual((await self.db.guild(GUILD))["verify_message_id"], f"{CHANNEL}:555")

    async def test_no_channel_means_no_post(self):
        self.assertFalse(await self.bot.post_message(GUILD, "honeypot"))

    async def test_the_honeypot_warning_is_pinned(self):
        document = await self.service.get_settings(GUILD)
        document["honeypot"].update(enabled=True, channel=LOG_CHANNEL)
        await self.service.save_settings(GUILD, document)
        self.port.pin = AsyncMock(return_value=True)
        self.assertTrue(await self.bot.post_message(GUILD, "honeypot"))
        self.port.pin.assert_awaited_once()

    async def test_help_button_only_with_the_help_desk_on(self):
        await self.bot.post_message(GUILD, "verification")
        notice = self.port.sent[-1][1]
        self.assertEqual([button.custom_id for button in notice.buttons], ["aw:verify"])
        document = await self.service.get_settings(GUILD)
        document["core"]["help_desk"].update(enabled=True, support_role=VERIFIED_ROLE)
        await self.service.save_settings(GUILD, document)
        await self.bot.post_message(GUILD, "verification")
        self.assertEqual([button.custom_id for button in self.port.sent[-1][1].buttons], ["aw:verify", "aw:help"])


class WhatDiscordReceives(Client):
    """The payload tree.sync() sends, checked against the limits in Discord's application commands topic."""

    def payloads(self):
        return [command.to_dict(self.bot.tree) for command in self.bot.tree.get_commands()]

    async def test_names_and_descriptions_fit(self):
        import re
        for row in self.payloads():
            if row["type"] != 1:
                self.assertLessEqual(len(row["name"]), 32)
                continue
            self.assertRegex(row["name"], r"^[-_a-z0-9]{1,32}$")
            self.assertTrue(1 <= len(row["description"]) <= 100, row["name"])
            for option in row.get("options", []):
                self.assertRegex(option["name"], r"^[-_a-z0-9]{1,32}$")
                self.assertTrue(1 <= len(option["description"]) <= 100, option["name"])
                self.assertNotEqual(option["description"], "\u2026", f"{row['name']}: {option['name']} has no description")
        del re

    async def test_no_more_user_commands_than_discord_allows(self):
        menus = [row for row in self.payloads() if row["type"] == 2]
        self.assertEqual(sorted(row["name"] for row in menus), ["Create Bypass", "Lookup", "Reset", "Verify"])
        self.assertLessEqual(len(menus), 5)

    async def test_staff_commands_stay_out_of_dms(self):
        everywhere = {"my-data", "help", "ping"}
        for row in self.payloads():
            if row["name"] not in everywhere:
                self.assertEqual(row.get("contexts"), [0], row["name"])


class ServersComingAndGoing(Client):
    async def test_removal_starts_the_clock_and_rejoining_stops_it(self):
        guild = SimpleNamespace(id=int(GUILD))
        await self.bot.on_guild_remove(guild)
        self.assertIsNotNone((await self.db.guild(GUILD))["left_at"])
        await self.bot.on_guild_join(guild)
        self.assertIsNone((await self.db.guild(GUILD))["left_at"])


class Replies(unittest.TestCase):
    def test_a_result_shows_when_to_come_back(self):
        result = Result("failed", "Stopped", "Too new.", retry_on=time.time() + 3600)
        self.assertIn("<t:", result_embed(result).description)

    def test_a_pass_is_green(self):
        self.assertEqual(result_embed(Result("verified", "Yes", "In.")).color.value, 0x2FBF71)


class Hooks(Client):
    async def test_honeypot_sees_posts_in_threads_under_the_trap(self):
        document = await self.service.get_settings(GUILD)
        document["honeypot"].update(enabled=True, channel=LOG_CHANNEL, action="log")
        await self.service.save_settings(GUILD, document)
        message = SimpleNamespace(
            guild=SimpleNamespace(id=int(GUILD)), id=7, webhook_id=None, is_system=lambda: False,
            author=SimpleNamespace(id=int(OTHER_USER), name="spam", roles=(), bot=False),
            channel=SimpleNamespace(id=99999999999999999, parent_id=int(LOG_CHANNEL)))
        await self.bot.on_message(message)
        self.assertTrue(self.port.did("delete_message"))

    async def test_a_system_message_in_the_trap_is_nobodys_post(self):
        document = await self.service.get_settings(GUILD)
        document["honeypot"].update(enabled=True, channel=LOG_CHANNEL, action="ban")
        await self.service.save_settings(GUILD, document)
        message = SimpleNamespace(
            guild=SimpleNamespace(id=int(GUILD)), id=7, webhook_id=None, is_system=lambda: True,
            author=SimpleNamespace(id=int(STAFF), name="staff", roles=(), bot=False),
            channel=SimpleNamespace(id=int(LOG_CHANNEL), parent_id=None))
        await self.bot.on_message(message)
        self.assertFalse(self.port.did("ban"))

    async def test_a_server_added_while_offline_gets_a_row(self):
        await self.db.run("DELETE FROM guilds")
        self.bot.tree.sync = AsyncMock()
        guild = SimpleNamespace(id=int(GUILD))
        self.bot._connection._guilds = {}
        type(self.bot).guilds = property(lambda _: [guild])
        try:
            await self.bot.on_ready()
        finally:
            del type(self.bot).guilds
        self.assertIsNotNone(await self.db.guild(GUILD))


if __name__ == "__main__":
    unittest.main()

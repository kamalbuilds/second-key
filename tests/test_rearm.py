"""Re-arming after a change that weakens the policy needs the armed roster's approval; strengthening does not."""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gateway.session_context import clear_session_vars, set_session_vars

ROOT = Path(__file__).resolve().parents[1] / "second-key"
spec = importlib.util.spec_from_file_location("second_key_rearm", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
quorum, tripwire = plugin.quorum, plugin.tripwire

SETTINGS = {"approvers": [{"name": "Priya", "telegram_id": "111"}, {"name": "Dev", "telegram_id": "222"},
                          {"name": "Sam", "telegram_id": "333"}],
            "required": 1, "critical_required": 2, "unknown_requester_required": 2, "critical_patterns": [r"rm\s+-rf"]}


def with_changes(**changes):
    return {**SETTINGS, **changes}


class WeakenedPolicyTests(unittest.TestCase):
    def weak(self, new, old=SETTINGS):
        return quorum.weakened(old, new)

    def test_fewer_votes_required_is_weaker(self):
        for key in ("required", "critical_required", "unknown_requester_required"):
            old = with_changes(**{key: 3})
            self.assertEqual(len(self.weak(with_changes(**{key: 2}), old)), 1, key)

    def test_a_removed_or_replaced_approver_is_weaker(self):
        gone = with_changes(approvers=SETTINGS["approvers"][:2])
        self.assertEqual(self.weak(gone), ["approver Sam removed"])
        swapped = with_changes(approvers=SETTINGS["approvers"][:2] + [{"name": "Eve", "telegram_id": "444"}])
        self.assertEqual(self.weak(swapped), ["approver Sam removed"])

    def test_a_dropped_critical_pattern_is_weaker_and_an_added_one_is_not(self):
        self.assertEqual(self.weak(with_changes(critical_patterns=[])), ["critical pattern dropped: rm\\s+-rf"])
        self.assertEqual(self.weak(with_changes(critical_patterns=[r"rm\s+-rf", "shutdown"])), [])

    def test_replacing_the_defaults_with_a_shorter_list_is_weaker(self):
        old = {k: v for k, v in SETTINGS.items() if k != "critical_patterns"}
        out = self.weak(with_changes(critical_patterns=["shutdown"]), old)
        self.assertTrue(out and out[0].startswith("critical pattern dropped"), out)

    def test_an_alias_on_a_local_session_is_weaker_and_a_chat_alias_is_not(self):
        local = with_changes(approvers=[{**SETTINGS["approvers"][0], "aliases": ["local:uid:501"]}] + SETTINGS["approvers"][1:])
        self.assertEqual(self.weak(local), ["Priya now aliases local:uid:501"])
        chat = with_changes(approvers=[{**SETTINGS["approvers"][0], "aliases": ["discord:42"]}] + SETTINGS["approvers"][1:])
        self.assertEqual(self.weak(chat), [])

    def test_stronger_or_equal_changes_are_not_weaker(self):
        more = with_changes(approvers=SETTINGS["approvers"] + [{"name": "Eve", "telegram_id": "444"}],
                            required=2, critical_required=3, critical_patterns=[r"rm\s+-rf", "shutdown"])
        self.assertEqual(self.weak(more), [])
        self.assertEqual(self.weak(SETTINGS), [])

    def test_settings_that_do_not_parse_count_as_weaker(self):
        self.assertEqual(self.weak({"approvers": "nobody"}), ["new settings do not parse: approvers must be a list"])

    def test_a_removed_settings_block_removes_every_approver(self):
        out = self.weak(None)
        self.assertEqual(out[:3], ["approver Priya removed", "approver Dev removed", "approver Sam removed"])


class LoosenedGateTests(unittest.TestCase):
    def test_new_allowlist_entries_and_dropped_deny_rules_are_weaker(self):
        before = {"command_allowlist": ["a"], "approvals_deny": ["rm *", "dd *"]}
        self.assertEqual(tripwire.loosened(before, {"command_allowlist": ["a", "recursive delete"], "approvals_deny": ["rm *", "dd *"]}),
                         ["command_allowlist adds recursive delete"])
        self.assertEqual(tripwire.loosened(before, {"command_allowlist": ["a"], "approvals_deny": ["rm *"]}),
                         ["approvals.deny drops dd *"])

    def test_a_shorter_allowlist_and_more_deny_rules_are_not_weaker(self):
        before = {"command_allowlist": ["a", "b"], "approvals_deny": ["rm *"]}
        self.assertEqual(tripwire.loosened(before, {"command_allowlist": ["a"], "approvals_deny": ["rm *", "dd *"]}), [])


CFG = """security:
  approval:
    transport: secondkey
approvals:
  mode: manual
plugins:
  entries:
    second-key:
      settings:
        approvers:
          - {name: Priya, telegram_id: "111"}
          - {name: Dev, telegram_id: "222"}
          - {name: Sam, telegram_id: "333"}
        required: 1
        critical_required: 2
        unknown_requester_required: 2
"""


class FakeBot:
    def __init__(self, votes):
        self.votes, self.sent, self.edits, self.closed, self.notes = votes, [], [], [], []

    def send_ballot(self, chat_id, text, request_id):
        self.sent.append((chat_id, text))
        if chat_id in self.votes:
            plugin._on_vote(request_id, chat_id, self.votes[chat_id])
        return len(self.sent)

    def edit_ballot(self, *args):
        self.edits.append(args)

    def close_ballot(self, *args):
        self.closed.append(args)

    def notify(self, chat_id, text):
        self.notes.append((chat_id, text))

    def call(self, method, payload, timeout=15):
        return {}


class RearmTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        (self.home / "config.yaml").write_text(CFG)
        self.env = patch.dict(os.environ, {"HERMES_HOME": str(self.home)})
        self.env.start()
        self.saved = (plugin._bot, plugin._ctx, plugin._get_ledger)
        self.bot = FakeBot({})
        plugin._bot = lambda: (self.bot, SimpleNamespace(ensure_running=lambda: None))
        plugin._ctx = _Ctx()
        plugin._ledger = None
        plugin._armed_view, plugin._tripped, plugin._tripped_alerted, plugin._cfg_stamp = None, [], False, None
        plugin._recent.clear()
        plugin._load_armed()
        self.assertIsNotNone(plugin._armed_view)
        self.tokens = set_session_vars(platform="local", user_id="uid:501")

    def tearDown(self):
        clear_session_vars(self.tokens)
        plugin._bot, plugin._ctx, plugin._get_ledger = self.saved
        plugin._armed_view, plugin._tripped, plugin._tripped_alerted, plugin._cfg_stamp = None, [], False, None
        plugin._ledger = None
        plugin._bindings.clear()
        plugin._ballots.clear()
        plugin._lives.clear()
        self.env.stop()
        self.temp.cleanup()

    def edit(self, old, new):
        path = self.home / "config.yaml"
        path.write_text(path.read_text().replace(old, new))
        future = time.time() + 2
        os.utime(path, (future, future))

    def tool(self):
        return plugin._on_pre_tool_call(tool_name="terminal", args={"command": "pytest -q"})

    def events(self):
        return [e["event"] for e in plugin._get_ledger().entries()]

    def test_a_weakening_edit_cannot_be_re_armed_without_the_old_roster(self):
        self.edit("critical_required: 2", "critical_required: 1")
        self.assertEqual(self.tool()["action"], "block")
        self.bot.votes = {"222": "deny"}
        out = plugin._cmd_secondkey("arm", platform="cli")
        self.assertIn("not re-armed", out)
        self.assertIn("critical_required", out)
        self.assertEqual(self.tool()["action"], "block", "still tripped")
        self.assertIn("rearm_denied", self.events())

    def test_the_ballot_names_the_change_and_goes_to_the_roster_that_was_armed(self):
        self.edit("required: 1", "required: 1")  # touch mtime only
        self.edit("critical_required: 2", "critical_required: 1")
        self.edit('          - {name: Sam, telegram_id: "333"}\n', "")  # Sam is gone from the new config
        self.bot.votes = {"222": "once", "333": "once"}
        plugin._cmd_secondkey("arm", platform="cli")
        chats = [c for c, _ in self.bot.sent]
        self.assertEqual(sorted(chats), ["111", "222", "333"], "all three armed approvers, Sam included")
        text = self.bot.sent[0][1]
        self.assertIn("re-arm second-key", text.lower())
        self.assertIn("critical_required 2 to 1", text)
        self.assertIn("approver Sam removed", text)

    def test_two_approvals_re_arm_and_the_ledger_shows_the_whole_story(self):
        self.edit("critical_required: 2", "critical_required: 1")
        self.assertEqual(self.tool()["action"], "block")
        self.bot.votes = {"222": "once", "333": "once"}
        out = plugin._cmd_secondkey("arm", platform="cli")
        self.assertIn("armed", out)
        self.assertNotIn("not re-armed", out)
        self.assertIsNone(self.tool())
        events = self.events()
        for want in ("rearm_requested", "presented", "decided", "armed"):
            self.assertIn(want, events)
        self.assertLess(events.index("rearm_requested"), events.index("decided"))
        self.assertLess(events.index("decided"), len(events) - 1 - events[::-1].index("armed"))
        armed = [e for e in plugin._get_ledger().entries() if e["event"] == "armed"][-1]
        self.assertEqual(armed["how"], "/secondkey arm (approved by Dev, Sam)")

    def test_one_approval_is_not_enough_when_two_are_required(self):
        self.edit("critical_required: 2", "critical_required: 1")
        self.bot.votes = {"222": "once"}
        with patch.object(plugin, "REARM_SECONDS", 3):
            out = plugin._cmd_secondkey("arm", platform="cli")
        self.assertIn("not re-armed", out)

    def test_a_stronger_change_re_arms_locally_with_no_ballot(self):
        self.edit("required: 1", "required: 2")
        self.assertEqual(self.tool()["action"], "block")
        out = plugin._cmd_secondkey("arm", platform="cli")
        self.assertIn("armed", out)
        self.assertEqual(self.bot.sent, [], "no ballot for a stronger policy")
        self.assertIsNone(self.tool())

    def test_a_new_allowlist_entry_needs_approval_too(self):
        self.edit("approvals:\n  mode: manual", "command_allowlist:\n  - recursive delete\napprovals:\n  mode: manual")
        self.bot.votes = {"222": "once", "333": "once"}
        plugin._cmd_secondkey("arm", platform="cli")
        self.assertIn("command_allowlist adds recursive delete", self.bot.sent[0][1])

    def test_a_roster_too_small_to_approve_cannot_be_weakened_at_all(self):
        (self.home / "config.yaml").write_text(CFG.replace('          - {name: Priya, telegram_id: "111"}\n', "")
                                               .replace('          - {name: Sam, telegram_id: "333"}\n', ""))
        plugin._armed_file().unlink()
        plugin._armed_view = None
        plugin._load_armed()
        self.assertEqual(len(plugin._armed_view["settings"]["approvers"]), 1)
        self.edit("critical_required: 2", "critical_required: 1")
        out = plugin._cmd_secondkey("arm", platform="cli")
        self.assertIn("not re-armed", out)
        self.assertEqual(self.bot.sent, [])
        self.assertEqual(self.tool()["action"], "block")

    def test_arm_from_a_chat_is_still_refused(self):
        self.edit("critical_required: 2", "critical_required: 1")
        self.assertIn("local", plugin._cmd_secondkey("arm", platform="telegram"))
        self.assertEqual(self.bot.sent, [])

    def test_first_arming_needs_no_ballot(self):
        plugin._armed_view = None
        out = plugin._cmd_secondkey("arm", platform="cli")
        self.assertIn("armed", out)
        self.assertEqual(self.bot.sent, [])


class _Ctx:
    def get_config(self, key, default=None):
        from hermes_cli.config import load_config_readonly
        cfg = load_config_readonly() or {}
        settings = ((cfg.get("plugins") or {}).get("entries") or {}).get("second-key", {}).get("settings") or {}
        return settings.get(key, default)


if __name__ == "__main__":
    unittest.main()

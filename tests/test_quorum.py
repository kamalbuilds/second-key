import importlib.util
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("second_key.quorum", ROOT / "second-key" / "quorum.py")
quorum = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = quorum
spec.loader.exec_module(quorum)


def policy(ids=("111", "222", "333"), **settings):
    return quorum.parse_policy({"approvers": [{"name": i, "telegram_id": i} for i in ids], **settings})


class QuorumTests(unittest.TestCase):
    def test_requester_vote_ignored(self):
        b = quorum.open_ballot(policy(), "r", "ls", quorum.Requester("telegram", "111"))
        self.assertEqual(b.vote("111", "once"), "ignored:requester")
        self.assertFalse(b.done.is_set())

    def test_non_roster_vote_ignored(self):
        b = quorum.open_ballot(policy(), "r", "ls", quorum.Requester("telegram", "111"))
        self.assertEqual(b.vote("999", "once"), "ignored:not-eligible")

    def test_one_of_n_approves_with_one_other_approver(self):
        b = quorum.open_ballot(policy(), "r", "ls", quorum.Requester("telegram", "111"))
        self.assertEqual(b.vote("222", "once"), "approved")
        self.assertEqual(b.outcome, "once")

    def test_critical_pattern_needs_two(self):
        b = quorum.open_ballot(policy(critical_patterns=["rm -rf"], critical_required=2), "r", "rm -rf /", quorum.Requester("telegram", "111"))
        self.assertEqual(b.required, 2)
        self.assertEqual(b.vote("222", "once"), "counted")
        self.assertEqual(b.vote("333", "once"), "approved")

    def test_unknown_requester_needs_two(self):
        b = quorum.open_ballot(policy(), "r", "ls", quorum.Requester())
        self.assertEqual(b.required, 2)

    def test_one_deny_closes_as_deny(self):
        b = quorum.open_ballot(policy(), "r", "ls", quorum.Requester("telegram", "111"))
        self.assertEqual(b.vote("222", "deny"), "denied")
        self.assertEqual(b.outcome, "deny")

    def test_impossible_ballot_is_done_and_deny(self):
        b = quorum.open_ballot(policy(("111",)), "r", "ls", quorum.Requester("telegram", "111"))
        self.assertTrue(b.done.is_set())
        self.assertTrue(b.impossible)
        self.assertEqual(b.outcome, "deny")

    def test_votes_after_close_are_ignored(self):
        b = quorum.open_ballot(policy(), "r", "ls", quorum.Requester("telegram", "111"))
        b.vote("222", "once")
        self.assertEqual(b.vote("333", "deny"), "ignored:closed")

    def test_alias_excludes_requester(self):
        p = quorum.parse_policy({"approvers": [
            {"telegram_id": "222", "aliases": ["discord:42"]}, {"telegram_id": "333"}
        ]})
        self.assertEqual([a.telegram_id for a in quorum.eligible_approvers(p, quorum.Requester("discord", "42"))], ["333"])

    def test_parse_policy_rejects_invalid_settings(self):
        bad = [
            ({"approvers": [{"telegram_id": "1"}, {"telegram_id": "1"}]}, "duplicate ids"),
            ({"approvers": [{"telegram_id": "abc"}]}, "non-numeric ids"),
            ({"required": 0}, "required 0"),
            ({"critical_patterns": ["["]}, "bad regex"),
        ]
        for cfg, label in bad[:-1]:
            with self.subTest(label=label), self.assertRaises(ValueError):
                quorum.parse_policy(cfg)
        with self.assertRaises(re.error):
            quorum.parse_policy(bad[-1][0])


if __name__ == "__main__":
    unittest.main()


class LiveViewTests(unittest.TestCase):
    def ballot(self, command="rm -rf /srv", requester=("telegram", "111"), **settings):
        return quorum.open_ballot(policy(critical_patterns=["rm -rf"], **settings), "r", command,
                                  quorum.Requester(*requester), timeout=60)

    def test_squares_fill_with_each_yes_and_never_overflow(self):
        b = self.ballot()
        self.assertEqual((b.squares(), b.progress()), ("□□", "0 of 2 approved"))
        b.vote("222", "once")
        self.assertEqual((b.squares(), b.progress()), ("■□", "1 of 2 approved: 222"))
        b.vote("333", "once")
        self.assertEqual((b.squares(), b.progress()), ("■■", "2 of 2 approved: 222, 333"))

    def test_waiting_on_drops_each_approver_who_voted_yes(self):
        b = self.ballot()
        self.assertEqual(b.waiting_on(), ["222", "333"])
        b.vote("222", "once")
        self.assertEqual(b.waiting_on(), ["333"])

    def test_risk_tier_follows_the_rule_that_set_the_vote_count(self):
        self.assertEqual(self.ballot().tier, "critical")
        self.assertEqual(self.ballot(command="ls").tier, "standard")
        self.assertEqual(self.ballot(command="ls", requester=("local", "uid:501")).tier, "unknown requester")

    def test_refused_taps_are_listed_by_name_with_the_reason(self):
        b = self.ballot()
        b.vote("111", "once")
        b.vote("999", "once")
        self.assertEqual([(n["name"], n["why"]) for n in b.not_counted], [("111", "requester"), ("999", "not-eligible")])
        self.assertEqual(b.yes, {})

    def test_snapshot_marks_requester_yes_and_waiting_and_carries_no_telegram_ids(self):
        b = self.ballot()
        b.vote("222", "once")
        snap = b.snapshot()
        self.assertEqual({a["name"]: a["state"] for a in snap["approvers"]}, {"111": "requester", "222": "yes", "333": "waiting"})
        self.assertEqual((snap["required"], snap["tier"], snap["timeout"]), (2, "critical", 60))
        self.assertNotIn("telegram_id", repr(snap))

    def test_snapshot_shows_the_approver_who_denied(self):
        b = self.ballot()
        b.vote("222", "deny")
        self.assertEqual({a["name"]: a["state"] for a in b.snapshot()["approvers"]}["222"], "no")

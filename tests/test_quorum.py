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

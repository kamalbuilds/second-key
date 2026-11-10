"""Which commands the built-in critical list catches, and the ways of writing them it must see through."""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("second_key.quorum", ROOT / "second-key" / "quorum.py")
quorum = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = quorum
spec.loader.exec_module(quorum)

POLICY = quorum.parse_policy({"approvers": [{"name": "A", "telegram_id": "1"}, {"name": "B", "telegram_id": "2"}]})
ASKER = quorum.Requester("telegram", "999")


def need(command, policy=POLICY):
    return quorum.required_votes(policy, command, ASKER)[0]


CRITICAL = (
    # flag order, combined flags, long flags
    "rm -rf /", "rm -fr /", "rm -r -f /x", "rm -f -r /x", "rm -r --force /x", "rm --recursive --force x", "rm -Rf x",
    "RM -RF x", "rm -rfv x", "rm -vrf x",
    # wrappers and chains
    "sh -c 'rm -rf /'", "bash -lc \"rm -r --force /srv\"", "sudo rm -rf /", "env X=1 rm --force -r /x",
    "echo hi; rm -r -f /", "true && rm --force -r /x", "ls | xargs rm -rf",
    "sh -c \"sh -c 'rm -r --force /x'\"",
    # other ways to delete
    "find . -delete", "find /srv -name '*.log' -exec rm {} \;",
    "python -c \"import shutil; shutil.rmtree('/srv')\"", "python3 -c 'import os; os.remove(\"/etc/hosts\")'",
    "truncate -s 0 /var/log/syslog", "shred -u secrets.txt", "wipefs -a /dev/sda",
    # SQL
    "psql -c 'DROP TABLE users'", "drop database prod", "psql -c 'DROP SCHEMA public CASCADE'",
    "psql -c 'TRUNCATE TABLE users'", "mysql -e 'drop user bob'",
    # git
    "git reset --hard", "git reset --hard HEAD~3", "git clean -fd", "git clean -f", "git branch -D main",
    "git push --force origin main", "git push origin main -f", "git push --force-with-lease",
    # permissions, disks
    "chmod -R 777 /", "chown -R root /srv", "chmod --recursive 000 /srv", "mkfs.ext4 /dev/sda1",
    "dd if=/dev/zero of=/dev/sda",
    # infrastructure
    "terraform destroy -auto-approve", "tofu destroy", "terraform apply -destroy", "pulumi destroy -y",
    "kubectl delete namespace prod", "kubectl delete ns prod", "kubectl delete deployment web", "kubectl delete pods --all",
    "helm uninstall web", "docker system prune -a", "docker volume rm data",
    "aws s3 rb s3://bucket --force", "aws s3 rm s3://bucket --recursive", "aws ec2 terminate-instances --instance-ids i-1",
    "aws rds delete-db-instance --db-instance-identifier prod", "gcloud compute instances delete vm1",
    "az group delete -n rg", "doctl compute droplet delete 1",
)
ORDINARY = (
    "ls -la", "rm notes.txt", "rm -r build", "rm -f stale.lock", "git push origin main", "git push origin feature-fix",
    "git reset HEAD file.txt", "git branch -d feature", "git clean -n", "git status", "chmod 644 notes.txt",
    "chown alice notes.txt", "kubectl delete pod web-1", "kubectl get pods --all-namespaces", "find . -name '*.py'",
    "dd if=a.img of=b.img", "terraform plan", "aws s3 ls", "docker ps", "echo drop tables", "psql -c 'select 1'",
    "python -c 'print(1)'", "truncate_logs.sh", "sh -c 'ls -la'",
)


class DefaultCriticalList(unittest.TestCase):
    def test_critical_commands_need_two_votes(self):
        for command in CRITICAL:
            with self.subTest(command):
                self.assertEqual(need(command), 2)

    def test_ordinary_commands_still_need_one(self):
        for command in ORDINARY:
            with self.subTest(command):
                self.assertEqual(need(command), 1)

    def test_a_configured_list_still_replaces_the_default_and_sees_unwrapped_commands(self):
        policy = quorum.parse_policy({"approvers": [{"name": "A", "telegram_id": "1"}],
                                      "critical_patterns": [r"shutdown"], "unknown_requester_required": 1})
        self.assertEqual(need("rm -rf /x", policy), 1)
        self.assertEqual(need("sh -c 'shutdown -h now'", policy), 2)

    def test_a_default_reason_names_the_rule_not_a_regex(self):
        _, reason = quorum.required_votes(POLICY, "git reset --hard", ASKER)
        self.assertEqual(reason, "critical pattern: git reset --hard")
        self.assertEqual(quorum.risk_tier(reason), "critical")

    def test_forms_unwrap_shell_payloads_and_expand_flags(self):
        forms = quorum.command_forms("sh -c 'cd /srv && rm -Rf --verbose build'")
        self.assertTrue(any("rm -r -f --verbose build" in f for f in forms), forms)

    def test_pathological_input_is_bounded(self):
        evil = "sh -c " * 200 + "'x'"
        self.assertLessEqual(len(quorum.command_forms(evil)), 64)
        self.assertEqual(need("(" * 5000), 1)
        self.assertEqual(need("'" * 5001), 1)


if __name__ == "__main__":
    unittest.main()

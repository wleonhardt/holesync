"""Unit tests for holesync's pure logic and sync flow (no real network).

Run: python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import holesync as hs  # noqa: E402


class TestNormalize(unittest.TestCase):
    def test_collapses_whitespace_and_drops_blanks(self):
        self.assertEqual(
            hs.normalize(["10.0.0.1   host", "  ", "10.0.0.2\tfoo"]),
            ["10.0.0.1 host", "10.0.0.2 foo"],
        )


class TestEquality(unittest.TestCase):
    def test_multiset_equal_order_insensitive(self):
        self.assertTrue(hs.multiset_equal(["a b", "c d"], ["c d", "a b"]))
        self.assertFalse(hs.multiset_equal(["a b"], ["a b", "c d"]))

    def test_multiset_equal_ignores_whitespace(self):
        self.assertTrue(hs.multiset_equal(["10.0.0.1   host"], ["10.0.0.1 host"]))

    def test_records_equal_respects_disabled_fields(self):
        src = hs.DnsRecords(hosts=["10.0.0.1 a"], cnames=["x,y"])
        dst = hs.DnsRecords(hosts=["10.0.0.1 a"], cnames=["DIFFERENT,z"])
        eq_opts = hs.Options(sync_hosts=True, sync_cnames=False)
        self.assertTrue(hs.records_equal(src, dst, eq_opts))
        all_opts = hs.Options(sync_hosts=True, sync_cnames=True)
        self.assertFalse(hs.records_equal(src, dst, all_opts))


class TestDiff(unittest.TestCase):
    def test_added_and_removed(self):
        added, removed = hs.diff(["a", "b", "c"], ["b", "c", "d"])
        self.assertEqual(added, ["a"])
        self.assertEqual(removed, ["d"])


class TestValidation(unittest.TestCase):
    def test_valid_host_entries(self):
        self.assertIsNone(hs.validate_host_entry("192.0.2.10 pihole.lan"))
        self.assertIsNone(hs.validate_host_entry("192.0.2.10 pihole"))
        self.assertIsNone(hs.validate_host_entry("fd00::1 host.lan"))

    def test_invalid_host_entries(self):
        self.assertIsNotNone(hs.validate_host_entry("not-an-ip host"))
        self.assertIsNotNone(hs.validate_host_entry("192.0.2.10"))  # no name
        self.assertIsNotNone(hs.validate_host_entry("192.0.2.10 bad name!"))

    def test_cname_entries(self):
        self.assertIsNone(hs.validate_cname_entry("alias.lan,target.lan"))
        self.assertIsNone(hs.validate_cname_entry("alias.lan,target.lan,300"))
        self.assertIsNotNone(hs.validate_cname_entry("only-one-field"))
        self.assertIsNotNone(hs.validate_cname_entry("a,b,notnum"))

    def test_validate_source_rejects_garbage(self):
        opts = hs.Options()
        with self.assertRaises(hs.SafetyAbort):
            hs.validate_source(hs.DnsRecords(hosts=["garbage entry no ip"]), opts)

    def test_validate_source_min_hosts_floor(self):
        opts = hs.Options(min_hosts=5)
        with self.assertRaises(hs.SafetyAbort):
            hs.validate_source(hs.DnsRecords(hosts=["10.0.0.1 a"]), opts)


class TestShrinkGuard(unittest.TestCase):
    def test_blocks_drastic_shrink(self):
        opts = hs.Options(max_shrink_pct=50)
        src = hs.DnsRecords(hosts=["10.0.0.1 a"])  # 1
        dst = hs.DnsRecords(hosts=["10.0.0.%d h%d" % (i, i) for i in range(10)])  # 10
        with self.assertRaises(hs.SafetyAbort):
            hs.shrink_guard(src, dst, opts)

    def test_allows_modest_change(self):
        opts = hs.Options(max_shrink_pct=50)
        src = hs.DnsRecords(hosts=["10.0.0.%d h%d" % (i, i) for i in range(8)])
        dst = hs.DnsRecords(hosts=["10.0.0.%d h%d" % (i, i) for i in range(10)])
        hs.shrink_guard(src, dst, opts)  # must not raise

    def test_force_bypasses(self):
        opts = hs.Options(max_shrink_pct=50, force=True)
        src = hs.DnsRecords(hosts=[])
        dst = hs.DnsRecords(hosts=["10.0.0.1 a", "10.0.0.2 b"])
        hs.shrink_guard(src, dst, opts)  # must not raise


class FakeClient:
    """Stand-in for PiholeClient that records writes against in-memory state."""

    def __init__(self, state: hs.DnsRecords, fail_verify=False):
        self.state = state
        self.fail_verify = fail_verify
        self.patches = []
        self._verify_pending = fail_verify

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_dns_records(self):
        return hs.DnsRecords(list(self.state.hosts), list(self.state.cnames))

    def patch_dns_records(self, rec, opts):
        self.patches.append((list(rec.hosts), list(rec.cnames)))
        if self._verify_pending:
            # Simulate a write that silently fails to apply, then a good rollback.
            self._verify_pending = False
            return
        self.state = hs.DnsRecords(list(rec.hosts), list(rec.cnames))


class TestProcessReplica(unittest.TestCase):
    def setUp(self):
        self.opts = hs.Options(backup_dir="")  # no disk backups in unit tests
        self.rcfg = hs.ReplicaConfig(name="r1", url="http://x", password="p")

    def _patch_client(self, fake):
        hs.PiholeClient = lambda *a, **k: fake  # type: ignore

    def tearDown(self):
        import importlib
        importlib.reload(hs)

    def test_no_change_when_in_sync(self):
        state = hs.DnsRecords(hosts=["10.0.0.1 a"])
        fake = FakeClient(state)
        self._patch_client(fake)
        src = hs.DnsRecords(hosts=["10.0.0.1 a"])
        res = hs.process_replica(self.rcfg, src, self.opts, "stamp")
        self.assertTrue(res.ok)
        self.assertTrue(res.in_sync)
        self.assertEqual(fake.patches, [])  # never wrote

    def test_writes_on_drift(self):
        fake = FakeClient(hs.DnsRecords(hosts=["10.0.0.1 a", "10.0.0.2 b"]))
        self._patch_client(fake)
        src = hs.DnsRecords(hosts=["10.0.0.1 a", "10.0.0.2 b", "10.0.0.3 c"])
        res = hs.process_replica(self.rcfg, src, self.opts, "stamp")
        self.assertTrue(res.ok)
        self.assertTrue(res.changed)
        self.assertEqual(len(fake.patches), 1)
        self.assertIn("10.0.0.3 c", fake.state.hosts)

    def test_dry_run_does_not_write(self):
        self.opts.dry_run = True
        fake = FakeClient(hs.DnsRecords(hosts=["10.0.0.1 a"]))
        self._patch_client(fake)
        src = hs.DnsRecords(hosts=["10.0.0.1 a", "10.0.0.2 b"])
        res = hs.process_replica(self.rcfg, src, self.opts, "stamp")
        self.assertTrue(res.ok)
        self.assertFalse(res.changed)
        self.assertEqual(fake.patches, [])

    def test_shrink_guard_aborts(self):
        fake = FakeClient(hs.DnsRecords(hosts=["10.0.0.%d h%d" % (i, i) for i in range(10)]))
        self._patch_client(fake)
        src = hs.DnsRecords(hosts=["10.0.0.1 a"])
        res = hs.process_replica(self.rcfg, src, self.opts, "stamp")
        self.assertFalse(res.ok)
        self.assertEqual(res.code, 3)
        self.assertEqual(fake.patches, [])

    def test_verify_failure_triggers_rollback(self):
        original = hs.DnsRecords(hosts=["10.0.0.1 a", "10.0.0.2 b"])
        fake = FakeClient(original, fail_verify=True)
        self._patch_client(fake)
        src = hs.DnsRecords(hosts=["10.0.0.1 a", "10.0.0.2 b", "10.0.0.3 c"])
        res = hs.process_replica(self.rcfg, src, self.opts, "stamp")
        self.assertFalse(res.ok)
        self.assertEqual(res.code, 4)
        # Two patches: the failed write, then the rollback.
        self.assertEqual(len(fake.patches), 2)
        self.assertIn("rollback succeeded", res.reason)


if __name__ == "__main__":
    unittest.main()

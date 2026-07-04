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

    def test_small_removals_allowed_despite_pct(self):
        # Removing a couple of records from a small set is a normal edit, not a
        # glitch — even though it exceeds the percentage, it's under shrink_min.
        opts = hs.Options(max_shrink_pct=50, shrink_min=5)
        hs.shrink_guard(hs.DnsRecords(hosts=[]),
                        hs.DnsRecords(hosts=["10.0.0.1 a"]), opts)        # 1 -> 0
        hs.shrink_guard(hs.DnsRecords(hosts=["10.0.0.1 a"]),
                        hs.DnsRecords(hosts=["10.0.0.%d h" % i for i in range(4)]),
                        opts)  # 4 -> 1, drop 3 <= shrink_min: allowed


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
        res = hs.process_replica(self.rcfg, hs.SourceState(dns=src), self.opts, "stamp")
        self.assertTrue(res.ok)
        self.assertTrue(res.in_sync)
        self.assertEqual(fake.patches, [])  # never wrote

    def test_writes_on_drift(self):
        fake = FakeClient(hs.DnsRecords(hosts=["10.0.0.1 a", "10.0.0.2 b"]))
        self._patch_client(fake)
        src = hs.DnsRecords(hosts=["10.0.0.1 a", "10.0.0.2 b", "10.0.0.3 c"])
        res = hs.process_replica(self.rcfg, hs.SourceState(dns=src), self.opts, "stamp")
        self.assertTrue(res.ok)
        self.assertTrue(res.changed)
        self.assertEqual(len(fake.patches), 1)
        self.assertIn("10.0.0.3 c", fake.state.hosts)

    def test_dry_run_does_not_write(self):
        self.opts.dry_run = True
        fake = FakeClient(hs.DnsRecords(hosts=["10.0.0.1 a"]))
        self._patch_client(fake)
        src = hs.DnsRecords(hosts=["10.0.0.1 a", "10.0.0.2 b"])
        res = hs.process_replica(self.rcfg, hs.SourceState(dns=src), self.opts, "stamp")
        self.assertTrue(res.ok)
        self.assertFalse(res.changed)
        self.assertEqual(fake.patches, [])

    def test_shrink_guard_aborts(self):
        fake = FakeClient(hs.DnsRecords(hosts=["10.0.0.%d h%d" % (i, i) for i in range(10)]))
        self._patch_client(fake)
        src = hs.DnsRecords(hosts=["10.0.0.1 a"])
        res = hs.process_replica(self.rcfg, hs.SourceState(dns=src), self.opts, "stamp")
        self.assertFalse(res.ok)
        self.assertEqual(res.code, 3)
        self.assertEqual(fake.patches, [])

    def test_verify_failure_triggers_rollback(self):
        original = hs.DnsRecords(hosts=["10.0.0.1 a", "10.0.0.2 b"])
        fake = FakeClient(original, fail_verify=True)
        self._patch_client(fake)
        src = hs.DnsRecords(hosts=["10.0.0.1 a", "10.0.0.2 b", "10.0.0.3 c"])
        res = hs.process_replica(self.rcfg, hs.SourceState(dns=src), self.opts, "stamp")
        self.assertFalse(res.ok)
        self.assertEqual(res.code, 4)
        # Two patches: the failed write, then the rollback.
        self.assertEqual(len(fake.patches), 2)
        self.assertIn("rollback succeeded", res.reason)


class TestLoadConfig(unittest.TestCase):
    import tempfile

    def _write(self, text):
        import tempfile
        fh = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        fh.write(text)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    _MIN = ("[source]\nurl = http://x\npassword = pw\n\n"
            "[replica:r1]\nurl = http://y\npassword = pw\n")

    def test_example_config_loads_verbatim(self):
        # B1: the shipped example uses inline ';' comments — must parse cleanly.
        example = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "holesync.conf.example")
        src, replicas, opts, _ = hs.load_config(example)
        self.assertEqual(src.name, "source")
        self.assertTrue(opts.sync_hosts)
        self.assertGreaterEqual(len(replicas), 1)

    def test_password_may_contain_percent(self):
        # B1: interpolation disabled — a '%' in a password is a literal.
        path = self._write(self._MIN.replace("password = pw", "password = pa%ss"))
        src, _, _, _ = hs.load_config(path)
        self.assertEqual(src.password, "pa%ss")

    def test_run_gravity_defaults_off(self):
        # B2: omitting run_gravity must NOT enable heavy gravity rebuilds.
        path = self._write(self._MIN + "\n[sync]\nhosts = true\n")
        _, _, opts, _ = hs.load_config(path)
        self.assertFalse(opts.run_gravity)

    def test_dotted_replica_name_preserved(self):
        # B3: [replica:pihole.lan] must keep its full name, not become 'lan'.
        path = self._write(self._MIN.replace("replica:r1", "replica:pihole.lan"))
        _, replicas, _, _ = hs.load_config(path)
        self.assertEqual(replicas[0].name, "pihole.lan")

    def test_unknown_section_rejected(self):
        # B3: a typo'd section must fail loudly, not be silently ignored.
        path = self._write(self._MIN + "\n[safty]\nmin_hosts = 5\n")
        with self.assertRaises(hs.HolesyncError):
            hs.load_config(path)

    def test_missing_url_is_config_error(self):
        path = self._write("[source]\npassword = pw\n\n[replica:r1]\nurl = http://y\npassword = pw\n")
        with self.assertRaises(hs.HolesyncError):
            hs.load_config(path)


class TestCheckExitCode(unittest.TestCase):
    def test_all_in_sync(self):
        rs = [hs.Result("a", ok=True, in_sync=True)]
        self.assertEqual(hs.check_exit_code(rs), 0)

    def test_drift_returns_10(self):
        rs = [hs.Result("a", ok=True, in_sync=False)]
        self.assertEqual(hs.check_exit_code(rs), 10)

    def test_failure_dominates_drift(self):
        # B4: an unreachable replica must not be reported as "in sync".
        rs = [hs.Result("a", ok=True, in_sync=False),
              hs.Result("b", ok=False, code=1)]
        self.assertEqual(hs.check_exit_code(rs), 1)

    def test_failure_over_in_sync(self):
        rs = [hs.Result("a", ok=True, in_sync=True),
              hs.Result("b", ok=False, code=1)]
        self.assertEqual(hs.check_exit_code(rs), 1)


class TestBackupRotation(unittest.TestCase):
    def _dir(self):
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def _touch(self, d, name):
        open(os.path.join(d, name), "w").close()

    def test_dns_and_collection_pools_are_independent(self):
        # B5: rotating the DNS series must not evict the collection series
        # (the old "name-" prefix matched "name-domains-…" too).
        d = self._dir()
        opts = hs.Options(backup_dir=d, backup_keep=2)
        stamps = ["20260101T000001", "20260101T000002", "20260101T000003"]
        for s in stamps:
            self._touch(d, "r1-%s.json" % s)          # DNS backups
            self._touch(d, "r1-domains-%s.json" % s)  # collection backups
        hs._rotate_backups("r1", opts)                # rotate DNS series only
        left = sorted(os.listdir(d))
        # DNS trimmed to 2; all 3 domain backups untouched.
        self.assertEqual([f for f in left if "domains" not in f],
                         ["r1-20260101T000002.json", "r1-20260101T000003.json"])
        self.assertEqual(len([f for f in left if "domains" in f]), 3)

    def test_collection_series_trimmed_by_kind(self):
        d = self._dir()
        opts = hs.Options(backup_dir=d, backup_keep=1)
        for s in ["20260101T000001", "20260101T000002"]:
            self._touch(d, "r1-clients-%s.json" % s)
        hs._rotate_backups("r1-clients", opts)
        self.assertEqual(os.listdir(d), ["r1-clients-20260101T000002.json"])


class TestLock(unittest.TestCase):
    def _path(self):
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return os.path.join(d, "sub", "holesync.lock")

    def test_second_acquire_is_blocked(self):
        p = self._path()
        a = hs.acquire_lock(p)              # creates parent dir too
        self.assertIsNotNone(a)
        b = hs.acquire_lock(p)
        self.assertIsNone(b)               # already held
        a.close()                          # releasing lets it be re-taken
        c = hs.acquire_lock(p)
        self.assertIsNotNone(c)
        c.close()

    def test_failed_acquire_preserves_holder_pid(self):
        # Opening must not truncate a held lockfile.
        p = self._path()
        a = hs.acquire_lock(p)
        with open(p) as fh:
            self.assertEqual(fh.read().strip(), str(os.getpid()))
        self.assertIsNone(hs.acquire_lock(p))  # second attempt
        with open(p) as fh:
            self.assertEqual(fh.read().strip(), str(os.getpid()))  # still intact
        a.close()


class TestReplicaIsolation(unittest.TestCase):
    def test_unexpected_error_becomes_failure_result(self):
        # W2: a KeyError from a malformed replica item must be caught per-replica,
        # not propagate and abort every other replica.
        class Boom:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def get_dns_records(self): raise KeyError("type")
        hs.PiholeClient = lambda *a, **k: Boom()  # type: ignore
        self.addCleanup(lambda: __import__("importlib").reload(hs))
        import logging
        logging.disable(logging.CRITICAL)          # silence the expected traceback
        self.addCleanup(logging.disable, logging.NOTSET)
        rcfg = hs.ReplicaConfig(name="r1", url="http://x", password="p")
        res = hs.process_replica(rcfg, hs.SourceState(dns=hs.DnsRecords(hosts=["10.0.0.1 a"])),
                                 hs.Options(backup_dir=""), "stamp")
        self.assertFalse(res.ok)
        self.assertEqual(res.code, 1)


class TestGroupMapping(unittest.TestCase):
    def test_group_maps(self):
        items = [{"id": 0, "name": "Default"}, {"id": 3, "name": "Kids"}]
        id2name, name2id = hs.group_maps(items)
        self.assertEqual(id2name, {0: "Default", 3: "Kids"})
        self.assertEqual(name2id, {"Default": 0, "Kids": 3})

    def test_translate_groups_by_name(self):
        # Source: Kids=3. Replica: Kids=7. A source item on group 3 must map to 7.
        src_id2name = {0: "Default", 3: "Kids"}
        dst_name2id = {"Default": 0, "Kids": 7}
        item = {"groups": [3]}
        self.assertEqual(hs._translate_groups(item, src_id2name, dst_name2id), [7])

    def test_translate_drops_unknown_group(self):
        # A source group with no matching name on the replica is dropped, not guessed.
        item = {"groups": [9]}
        self.assertEqual(hs._translate_groups(item, {9: "Ghost"}, {"Default": 0}), [])


class TestPlanCollection(unittest.TestCase):
    def setUp(self):
        # Same group ids on both sides for simplicity.
        self.s_id2name = {0: "Default"}
        self.d_id2name = {0: "Default"}

    def test_add_update_delete_domains(self):
        def dom(d, enabled=True, comment=""):
            return {"type": "allow", "kind": "exact", "domain": d,
                    "enabled": enabled, "comment": comment, "groups": [0]}
        source = [dom("a.com"), dom("b.com", enabled=False)]
        current = [dom("a.com"), dom("c.com")]
        add, upd, dele = hs.plan_collection(hs.DOMAINS, source, current,
                                            self.s_id2name, self.d_id2name)
        self.assertEqual([x["domain"] for x in add], ["b.com"])
        self.assertEqual([x["domain"] for x in dele], ["c.com"])
        self.assertEqual(upd, [])  # a.com identical on both

    def test_update_detected_on_enabled_change(self):
        def dom(enabled):
            return {"type": "deny", "kind": "exact", "domain": "x.com",
                    "enabled": enabled, "comment": "", "groups": [0]}
        add, upd, dele = hs.plan_collection(hs.DOMAINS, [dom(False)], [dom(True)],
                                            self.s_id2name, self.d_id2name)
        self.assertEqual(len(upd), 1)
        self.assertEqual(add, [])
        self.assertEqual(dele, [])

    def test_group_membership_change_is_an_update(self):
        # Same domain, different group name set -> update.
        src_id2name = {0: "Default", 1: "Kids"}
        dst_id2name = {0: "Default", 5: "Kids"}
        s = [{"type": "allow", "kind": "exact", "domain": "x", "enabled": True,
              "comment": "", "groups": [0, 1]}]
        c = [{"type": "allow", "kind": "exact", "domain": "x", "enabled": True,
              "comment": "", "groups": [0]}]
        add, upd, dele = hs.plan_collection(hs.DOMAINS, s, c, src_id2name, dst_id2name)
        self.assertEqual(len(upd), 1)

    def test_clients_plan_with_group_remap(self):
        # Clients reference groups by id; compare by group NAME across Pi-holes.
        src_id2name = {0: "Default", 1: "Kids"}
        dst_id2name = {0: "Default", 6: "Kids"}
        s = [{"client": "10.0.0.5", "comment": "tv", "groups": [1]},
             {"client": "aa:bb:cc:dd:ee:ff", "comment": "", "groups": [0]}]
        c = [{"client": "10.0.0.5", "comment": "tv", "groups": [6]},   # same (Kids on both)
             {"client": "10.0.0.9", "comment": "old", "groups": [0]}]  # not in source
        add, upd, dele = hs.plan_collection(hs.CLIENTS, s, c, src_id2name, dst_id2name)
        self.assertEqual([x["client"] for x in add], ["aa:bb:cc:dd:ee:ff"])
        self.assertEqual([x["client"] for x in dele], ["10.0.0.9"])
        self.assertEqual(upd, [])  # 10.0.0.5 matches once groups are name-mapped

    def test_default_group_protected_from_delete(self):
        source = []  # source has no groups
        current = [{"id": 0, "name": "Default", "enabled": True, "comment": ""},
                   {"id": 4, "name": "Kids", "enabled": True, "comment": ""}]
        add, upd, dele = hs.plan_collection(hs.GROUPS, source, current, {}, {})
        names = [x["name"] for x in dele]
        self.assertIn("Kids", names)
        self.assertNotIn("Default", names)  # never deleted


class TestBatching(unittest.TestCase):
    def _dom(self, d, comment="", groups=(0,)):
        return {"type": "allow", "kind": "exact", "domain": d, "enabled": True,
                "comment": comment, "groups": list(groups)}

    def test_homogeneous_adds_collapse_to_one_post(self):
        items = [self._dom("a.com"), self._dom("b.com"), self._dom("c.com")]
        out = hs.bucket_adds(hs.DOMAINS, items, lambda it: [0])
        self.assertEqual(len(out), 1)                       # one POST for all three
        path, body = out[0]
        self.assertEqual(path, "/api/domains/allow/exact")
        self.assertEqual(sorted(body["domain"]), ["a.com", "b.com", "c.com"])
        self.assertEqual(body["groups"], [0])

    def test_differing_attrs_split_into_separate_posts(self):
        items = [self._dom("a.com", comment="x"), self._dom("b.com", comment="y")]
        out = hs.bucket_adds(hs.DOMAINS, items, lambda it: [0])
        self.assertEqual(len(out), 2)                       # different comments -> 2 POSTs

    def test_group_remap_applied_in_payload(self):
        # gids_fn simulates name-based remap: source group ids -> replica ids.
        items = [self._dom("a.com", groups=[1])]
        out = hs.bucket_adds(hs.DOMAINS, items, lambda it: [7])
        self.assertEqual(out[0][1]["groups"], [7])

    def test_delete_keys_carry_type_and_kind(self):
        key = hs.DOMAINS.delete_key(self._dom("a.com"))
        self.assertEqual(key, {"item": "a.com", "type": "allow", "kind": "exact"})


class FakeCollClient:
    name = "fake"

    def __init__(self, items_by_kind):
        self.items_by_kind = items_by_kind
        self.writes = []

    def get_collection(self, kind):
        return list(self.items_by_kind.get(kind, []))

    def write_item(self, m, p, b):
        self.writes.append((m, p, b))
        return 200, {}

    def batch_delete(self, kind, keys):
        self.writes.append(("BATCHDELETE", kind, keys))
        return 200, {}


class TestCollectionGuards(unittest.TestCase):
    def _dom(self, d):
        return {"type": "allow", "kind": "exact", "domain": d,
                "enabled": True, "comment": "", "groups": [0]}

    def test_change_cap_aborts_bulk(self):
        opts = hs.Options(max_changes=25, backup_dir="")
        client = FakeCollClient({"domains": []})
        source = [self._dom("d%d.com" % i) for i in range(40)]  # 40 adds > 25
        with self.assertRaises(hs.SafetyAbort):
            hs.sync_collection(client, hs.DOMAINS, source, opts, {0: "Default"},
                               {"Default": 0}, {0: "Default"}, "stamp")
        self.assertEqual(client.writes, [])  # nothing written

    def test_shrink_guard_aborts_mass_delete(self):
        opts = hs.Options(max_shrink_pct=50, max_changes=1000, backup_dir="")
        current = [self._dom("d%d.com" % i) for i in range(10)]
        client = FakeCollClient({"domains": current})
        with self.assertRaises(hs.SafetyAbort):
            hs.sync_collection(client, hs.DOMAINS, [], opts, {0: "Default"},
                               {"Default": 0}, {0: "Default"}, "stamp")
        self.assertEqual(client.writes, [])

    def test_in_sync_no_writes(self):
        opts = hs.Options(backup_dir="")
        items = [self._dom("a.com")]
        client = FakeCollClient({"domains": items})
        changed, drifted = hs.sync_collection(client, hs.DOMAINS, items, opts,
                                              {0: "Default"}, {"Default": 0},
                                              {0: "Default"}, "stamp")
        self.assertFalse(changed)
        self.assertFalse(drifted)
        self.assertEqual(client.writes, [])


DOM_ITEM = {"type": "allow", "kind": "exact", "domain": "a.com",
            "enabled": True, "comment": "", "groups": [0]}


class FakeGravityClient:
    name = "fake"

    def __init__(self, probe_rtt=0.1, messages=None, collections=None):
        self._probe = probe_rtt
        self._messages = messages or []
        self._collections = collections or {}
        self.calls = []

    def get_messages(self):
        return list(self._messages)

    def probe(self):
        return self._probe

    def get_collection(self, kind):
        self.calls.append(("GET", kind))
        return list(self._collections.get(kind, []))

    def write_item(self, *a):
        self.calls.append(("WRITE", a))
        return 200, {}

    def batch_delete(self, *a):
        self.calls.append(("DEL", a))
        return 200, {}


class TestPreflight(unittest.TestCase):
    def _src(self):
        return hs.SourceState(
            dns=hs.DnsRecords(),
            domains=[dict(DOM_ITEM)],
            group_id2name={0: "Default"},
        )

    def test_db_health_messages_matches_corruption(self):
        c = FakeGravityClient(messages=[
            {"type": "DATABASE", "message": "database disk image is malformed"},
            {"type": "RATE_LIMIT", "message": "client x rate-limited"},
        ])
        hits = hs.db_health_messages(c)
        self.assertEqual(len(hits), 1)

    def test_unhealthy_replica_refuses_to_write(self):
        opts = hs.Options(sync_domains=True, backup_dir="")
        c = FakeGravityClient(messages=[{"type": "DATABASE", "message": "malformed"}])
        with self.assertRaises(hs.SafetyAbort):
            hs._sync_gravity(c, self._src(), opts, "stamp", "r1")
        self.assertEqual(c.calls, [])   # never touched the collections

    def test_busy_replica_defers_writes(self):
        opts = hs.Options(sync_domains=True, load_probe_max=5.0, backup_dir="")
        c = FakeGravityClient(probe_rtt=99.0)   # slow == busy
        changed, drifted = hs._sync_gravity(c, self._src(), opts, "stamp", "r1")
        self.assertFalse(changed)
        self.assertEqual(c.calls, [])   # deferred before any collection access

    def test_responsive_replica_proceeds(self):
        opts = hs.Options(sync_domains=True, load_probe_max=5.0, backup_dir="")
        # Replica already matches source (groups + the one domain) -> in sync.
        c = FakeGravityClient(probe_rtt=0.05, collections={
            "groups": [{"id": 0, "name": "Default"}],
            "domains": [dict(DOM_ITEM)],
        })
        changed, drifted = hs._sync_gravity(c, self._src(), opts, "stamp", "r1")
        self.assertFalse(changed)
        self.assertFalse(drifted)                       # responsive + already in sync
        self.assertIn(("GET", "domains"), c.calls)      # proceeded past the probe


if __name__ == "__main__":
    unittest.main()

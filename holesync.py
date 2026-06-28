#!/usr/bin/env python3
"""holesync — a lightweight Pi-hole v6 configuration replicator.

Mirrors local DNS records (and, optionally, list definitions) from a primary
Pi-hole to one or more replicas using the Pi-hole v6 REST API.

Design goals
------------
* **Minimal downtime.** Changes are applied through the live configuration API,
  which reloads DNS in place rather than restarting the resolver. The replica's
  :53 socket is never torn down, so in-flight queries are not dropped. On top of
  that, holesync is *diff-gated*: if a replica already matches the source it is
  not written to at all, so a steady-state sync causes zero reloads.

* **Corruption-safe.** Before writing, the source data is validated and a couple
  of guardrails run (a minimum-record floor and a "don't let the data set shrink
  drastically" check) so a transient glitch on the source can never wipe a good
  replica. The replica's current state is backed up to disk first, the write is
  verified afterwards, and a failed verification is automatically rolled back.

* **Dependency-free.** Python 3 standard library only. Runs anywhere there is a
  python3 interpreter, including old/low-power hardware.

Exit codes
----------
  0  success (includes "already in sync — nothing to do")
  1  unexpected/runtime error
  2  configuration error
  3  safety guard aborted a replica (no change made)
  4  a write could not be verified (rollback attempted)
  5  another holesync run holds the lock
 10  --check only: at least one replica is out of sync (read-only)
"""

from __future__ import annotations

import argparse
import configparser
import dataclasses
import datetime
import fcntl
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from typing import Optional

__version__ = "1.1.0"

LOG = logging.getLogger("holesync")

# Hostnames permitted in a "IP hostname" dns.hosts entry. Deliberately permissive
# (single labels like "router" and FQDNs like "router.lan" both occur) but still
# rejects whitespace/control characters and obviously bogus values.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})\.?)+$")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class DnsRecords:
    """The slice of Pi-hole config holesync replicates."""

    hosts: list[str] = dataclasses.field(default_factory=list)
    cnames: list[str] = dataclasses.field(default_factory=list)

    def counts(self) -> tuple[int, int]:
        return len(self.hosts), len(self.cnames)


@dataclasses.dataclass
class ReplicaConfig:
    name: str
    url: str
    password: str


@dataclasses.dataclass
class Options:
    sync_hosts: bool = True
    sync_cnames: bool = True
    # Gravity-database collections (groups must sync before adlists/domains,
    # which reference groups by id — holesync remaps them by name).
    sync_groups: bool = False
    sync_adlists: bool = False
    sync_domains: bool = False
    # Trigger a gravity rebuild on a replica when its adlists change. OFF by
    # default: a rebuild is heavy and only adlist *content* needs it (allow/deny
    # domains and groups apply instantly without it). Leave off to let the
    # replica's own scheduled gravity cron pick up new adlists, or enable to
    # apply adlist changes immediately.
    run_gravity: bool = False
    timeout: float = 8.0               # per request, for fast (config/read) calls
    write_timeout: float = 30.0        # collection writes trigger a synchronous FTL reload — slower
    gravity_timeout: float = 180.0     # a gravity rebuild downloads + parses all adlists
    retries: int = 3
    verify_tls: bool = True
    min_hosts: int = 1
    max_shrink_pct: float = 50.0       # also caps deletions per gravity collection
    max_changes: int = 25              # per-collection write cap; over this, abort (use --force)
    backup_dir: str = ""
    backup_keep: int = 30
    dry_run: bool = False
    force: bool = False

    @property
    def sync_gravity(self) -> bool:
        """True if any gravity-database collection is enabled."""
        return self.sync_groups or self.sync_adlists or self.sync_domains


class HolesyncError(Exception):
    """Base class for expected, message-worthy failures."""


class AuthError(HolesyncError):
    pass


class ApiError(HolesyncError):
    pass


class SafetyAbort(HolesyncError):
    pass


# --------------------------------------------------------------------------- #
# Pure helpers (unit-tested without a network)
# --------------------------------------------------------------------------- #
def normalize(items: list[str]) -> list[str]:
    """Collapse internal whitespace and drop blanks, preserving order."""
    out = []
    for raw in items:
        s = " ".join(str(raw).split())
        if s:
            out.append(s)
    return out


def multiset_equal(a: list[str], b: list[str]) -> bool:
    """Order-insensitive equality (Pi-hole stores these as unordered lists)."""
    from collections import Counter

    return Counter(normalize(a)) == Counter(normalize(b))


def records_equal(src: DnsRecords, dst: DnsRecords, opts: Options) -> bool:
    if opts.sync_hosts and not multiset_equal(src.hosts, dst.hosts):
        return False
    if opts.sync_cnames and not multiset_equal(src.cnames, dst.cnames):
        return False
    return True


def diff(a: list[str], b: list[str]) -> tuple[list[str], list[str]]:
    """Return (added, removed) needed to turn *b* into *a* (set semantics)."""
    sa, sb = set(normalize(a)), set(normalize(b))
    return sorted(sa - sb), sorted(sb - sa)


def validate_host_entry(entry: str) -> Optional[str]:
    """Return an error string if *entry* is not a valid "IP host[ host...]" line."""
    parts = entry.split()
    if len(parts) < 2:
        return "expected 'IP hostname', got %r" % entry
    ip = parts[0]
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return "invalid IP %r in %r" % (ip, entry)
    for name in parts[1:]:
        if not _HOSTNAME_RE.match(name):
            return "invalid hostname %r in %r" % (name, entry)
    return None


def validate_cname_entry(entry: str) -> Optional[str]:
    """Pi-hole cnameRecords are 'alias,target' or 'alias,target,ttl'."""
    parts = entry.split(",")
    if len(parts) not in (2, 3):
        return "expected 'alias,target[,ttl]', got %r" % entry
    if not all(p.strip() for p in parts[:2]):
        return "empty alias/target in %r" % entry
    if len(parts) == 3 and not parts[2].strip().isdigit():
        return "non-numeric ttl in %r" % entry
    return None


def validate_source(src: DnsRecords, opts: Options) -> None:
    """Raise SafetyAbort if the source data looks malformed or implausible.

    This is the first line of defence against pushing garbage to a replica.
    """
    if opts.sync_hosts:
        for e in src.hosts:
            err = validate_host_entry(e)
            if err:
                raise SafetyAbort("source host record rejected: %s" % err)
        if len(src.hosts) < opts.min_hosts:
            raise SafetyAbort(
                "source has %d host records, below min_hosts=%d — refusing to sync"
                % (len(src.hosts), opts.min_hosts)
            )
    if opts.sync_cnames:
        for e in src.cnames:
            err = validate_cname_entry(e)
            if err:
                raise SafetyAbort("source cname record rejected: %s" % err)


def shrink_guard(src: DnsRecords, dst: DnsRecords, opts: Options) -> None:
    """Refuse a write that would shrink the replica's data set drastically.

    If the source suddenly reports far fewer records than the replica currently
    has, that is far more likely to be a source-side glitch than a real bulk
    deletion. Abort rather than propagate the loss. Override with --force.
    """
    if opts.force:
        return
    threshold = 1.0 - (opts.max_shrink_pct / 100.0)
    if opts.sync_hosts and len(dst.hosts) > 0:
        if len(src.hosts) < len(dst.hosts) * threshold:
            raise SafetyAbort(
                "host records would drop %d -> %d (> %.0f%% shrink) — "
                "refusing without --force"
                % (len(dst.hosts), len(src.hosts), opts.max_shrink_pct)
            )
    if opts.sync_cnames and len(dst.cnames) > 0:
        if len(src.cnames) < len(dst.cnames) * threshold:
            raise SafetyAbort(
                "cname records would drop %d -> %d (> %.0f%% shrink) — "
                "refusing without --force"
                % (len(dst.cnames), len(src.cnames), opts.max_shrink_pct)
            )


# --------------------------------------------------------------------------- #
# Pi-hole v6 API client
# --------------------------------------------------------------------------- #
class PiholeClient:
    """Minimal Pi-hole v6 REST client with retries and session handling."""

    def __init__(self, name: str, url: str, password: str, opts: Options):
        self.name = name
        self.base = url.rstrip("/")
        self._password = password
        self.opts = opts
        self.sid: Optional[str] = None
        self.csrf: Optional[str] = None
        self._ctx = None
        if self.base.startswith("https") and not opts.verify_tls:
            import ssl

            self._ctx = ssl._create_unverified_context()

    # -- low level ---------------------------------------------------------- #
    def _raw(self, method: str, path: str, body: Optional[dict], timeout: float):
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.sid:
            headers["X-FTL-SID"] = self.sid
        if self.csrf and method in ("POST", "PUT", "PATCH", "DELETE"):
            headers["X-FTL-CSRF"] = self.csrf
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self._ctx) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def _request(self, method: str, path: str, body: Optional[dict] = None,
                 timeout: Optional[float] = None,
                 max_attempts: Optional[int] = None) -> tuple[int, dict]:
        """Send a request, retrying transient failures with backoff."""
        if timeout is None:
            timeout = self.opts.timeout
        if max_attempts is None:
            max_attempts = self.opts.retries
        last_exc: Optional[Exception] = None
        for attempt in range(1, max_attempts + 1):
            try:
                status, raw = self._raw(method, path, body, timeout)
            except (urllib.error.URLError, socket.timeout, ConnectionError) as e:
                last_exc = e
                status, raw = 0, b""
            payload: dict = {}
            if raw:
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    payload = {}
            # Success, or a non-retryable client error — return immediately.
            if status and status < 500 and status != 429:
                return status, payload
            # Transient: connection failure, 5xx, or session exhaustion (429).
            if attempt < max_attempts:
                wait = min(2.0 ** (attempt - 1), 8.0)
                if status == 429:
                    wait = max(wait, 2.0)
                LOG.debug(
                    "[%s] %s %s -> %s, retry %d/%d in %.1fs",
                    self.name, method, path, status or "conn-err", attempt,
                    self.opts.retries, wait,
                )
                time.sleep(wait)
        if last_exc is not None and not status:
            raise ApiError("[%s] %s %s failed: %s" % (self.name, method, path, last_exc))
        return status, payload

    # -- auth --------------------------------------------------------------- #
    def auth(self) -> None:
        status, payload = self._request("POST", "/api/auth", {"password": self._password})
        session = (payload or {}).get("session", {})
        if status == 200 and session.get("valid") and session.get("sid"):
            self.sid = session["sid"]
            self.csrf = session.get("csrf")
            LOG.debug("[%s] authenticated (validity=%ss)", self.name, session.get("validity"))
            return
        msg = session.get("message") or (payload or {}).get("error", {}).get("message") or status
        raise AuthError("[%s] authentication failed: %s" % (self.name, msg))

    def logout(self) -> None:
        if not self.sid:
            return
        try:
            self._request("DELETE", "/api/auth")
        except HolesyncError:
            pass
        finally:
            self.sid = None
            self.csrf = None

    def __enter__(self) -> "PiholeClient":
        self.auth()
        return self

    def __exit__(self, *exc) -> None:
        self.logout()

    # -- config ------------------------------------------------------------- #
    def get_dns_records(self) -> DnsRecords:
        status, payload = self._request("GET", "/api/config/dns")
        if status != 200:
            raise ApiError("[%s] GET /api/config/dns -> %s" % (self.name, status))
        dns = (payload.get("config") or {}).get("dns") or {}
        return DnsRecords(
            hosts=list(dns.get("hosts") or []),
            cnames=list(dns.get("cnameRecords") or []),
        )

    def patch_dns_records(self, rec: DnsRecords, opts: Options) -> None:
        dns: dict = {}
        if opts.sync_hosts:
            dns["hosts"] = normalize(rec.hosts)
        if opts.sync_cnames:
            dns["cnameRecords"] = normalize(rec.cnames)
        if not dns:
            return
        status, payload = self._request("PATCH", "/api/config", {"config": {"dns": dns}})
        if status not in (200, 201):
            err = (payload or {}).get("error", {})
            raise ApiError(
                "[%s] PATCH /api/config -> %s: %s"
                % (self.name, status, err.get("message") or err or payload)
            )

    # -- gravity-database collections --------------------------------------- #
    def get_collection(self, kind: str) -> list[dict]:
        """kind ∈ {groups, lists, domains}. Returns the raw item list.

        Uses the longer write timeout: a collection read can immediately follow a
        write, and the replica may still be holding its database lock during the
        post-write list reload — the GET must wait that out rather than fail."""
        path = {"groups": "/api/groups", "lists": "/api/lists",
                "domains": "/api/domains"}[kind]
        status, payload = self._request("GET", path, timeout=self.opts.write_timeout)
        if status != 200:
            raise ApiError("[%s] GET %s -> %s" % (self.name, path, status))
        return list(payload.get(kind) or [])

    def write_item(self, method: str, path: str, body: Optional[dict]) -> tuple[int, dict]:
        """A collection mutation. These trigger a synchronous FTL list reload on
        the server, so they can be slow to respond — use the longer write timeout
        and a SINGLE attempt. A slow write often applies server-side even when the
        HTTP response times out; retrying at this layer would multiply the wait
        and risk overlapping reloads, so we tolerate the timeout and let the
        caller's read-back/converge step decide whether the change actually
        landed."""
        try:
            return self._request(method, path, body,
                                 timeout=self.opts.write_timeout, max_attempts=1)
        except HolesyncError:
            return 0, {}

    def run_gravity(self) -> bool:
        """Trigger a gravity rebuild (downloads/parses adlists). Best-effort:
        the rebuild proceeds server-side even if the HTTP response is slow."""
        try:
            status, _ = self._request("POST", "/api/action/gravity",
                                      timeout=self.opts.gravity_timeout)
            return status in (200, 201)
        except HolesyncError as e:
            LOG.warning("[%s] gravity rebuild request did not confirm: %s", self.name, e)
            return False


# --------------------------------------------------------------------------- #
# Gravity-database collection sync (groups, adlists, domains)
# --------------------------------------------------------------------------- #
def _q(s: str) -> str:
    return urllib.parse.quote(str(s), safe="")


@dataclasses.dataclass
class Collection:
    """Adapter describing how to read/compare/write one gravity collection."""

    kind: str                                   # groups | lists | domains
    key: "callable"                             # item -> hashable identity
    scalar_fields: tuple                        # compared fields besides the key + groups
    has_groups: bool                            # references groups by id?
    create_req: "callable"                      # (item, gids) -> (method, path, body)
    update_req: "callable"                      # (item, gids) -> (method, path, body)
    delete_req: "callable"                      # (item) -> (method, path)
    protect: "callable" = lambda it: False      # never delete these (e.g. Default group)


def _grp_names(item: dict, id2name: dict) -> list[str]:
    return sorted(id2name.get(g, "id:%s" % g) for g in item.get("groups", []))


def _comparable(coll: Collection, item: dict, id2name: dict) -> dict:
    c = {f: item.get(f) for f in coll.scalar_fields}
    if coll.has_groups:
        c["groups"] = _grp_names(item, id2name)
    return c


def _translate_groups(item: dict, src_id2name: dict, dst_name2id: dict) -> list[int]:
    """Map a source item's group ids -> names -> the replica's group ids."""
    out = set()
    for gid in item.get("groups", []):
        name = src_id2name.get(gid)
        if name is None:
            continue
        rid = dst_name2id.get(name)
        if rid is not None:
            out.add(rid)
    return sorted(out)


GROUPS = Collection(
    kind="groups",
    key=lambda it: it["name"],
    scalar_fields=("enabled", "comment"),
    has_groups=False,
    create_req=lambda it, g: ("POST", "/api/groups",
                              {"name": it["name"], "comment": it.get("comment") or "",
                               "enabled": bool(it["enabled"])}),
    update_req=lambda it, g: ("PUT", "/api/groups/" + _q(it["name"]),
                              {"name": it["name"], "comment": it.get("comment") or "",
                               "enabled": bool(it["enabled"])}),
    delete_req=lambda it: ("DELETE", "/api/groups/" + _q(it["name"])),
    protect=lambda it: it.get("name") == "Default" or it.get("id") == 0,
)

ADLISTS = Collection(
    kind="lists",
    key=lambda it: (it["type"], it["address"]),
    scalar_fields=("enabled", "comment"),
    has_groups=True,
    create_req=lambda it, g: ("POST", "/api/lists?type=" + _q(it["type"]),
                              {"address": it["address"], "comment": it.get("comment") or "",
                               "enabled": bool(it["enabled"]), "groups": g}),
    update_req=lambda it, g: ("PUT", "/api/lists/" + _q(it["address"]) + "?type=" + _q(it["type"]),
                              {"comment": it.get("comment") or "",
                               "enabled": bool(it["enabled"]), "groups": g}),
    delete_req=lambda it: ("DELETE", "/api/lists/" + _q(it["address"]) + "?type=" + _q(it["type"])),
)

DOMAINS = Collection(
    kind="domains",
    key=lambda it: (it["type"], it["kind"], it["domain"]),
    scalar_fields=("enabled", "comment"),
    has_groups=True,
    create_req=lambda it, g: ("POST", "/api/domains/%s/%s" % (_q(it["type"]), _q(it["kind"])),
                              {"domain": it["domain"], "comment": it.get("comment") or "",
                               "enabled": bool(it["enabled"]), "groups": g}),
    update_req=lambda it, g: ("PUT", "/api/domains/%s/%s/%s" % (_q(it["type"]), _q(it["kind"]), _q(it["domain"])),
                              {"comment": it.get("comment") or "",
                               "enabled": bool(it["enabled"]), "groups": g}),
    delete_req=lambda it: ("DELETE", "/api/domains/%s/%s/%s" % (_q(it["type"]), _q(it["kind"]), _q(it["domain"]))),
)


def plan_collection(coll: Collection, source: list[dict], current: list[dict],
                    src_id2name: dict, dst_id2name: dict):
    """Return (to_add, to_update, to_delete) item lists by comparing source→current."""
    src = {coll.key(it): it for it in source}
    cur = {coll.key(it): it for it in current}
    to_add = [src[k] for k in src if k not in cur]
    to_delete = [cur[k] for k in cur if k not in src and not coll.protect(cur[k])]
    to_update = [
        src[k] for k in src
        if k in cur
        and _comparable(coll, src[k], src_id2name) != _comparable(coll, cur[k], dst_id2name)
    ]
    return to_add, to_update, to_delete


def sync_collection(client: "PiholeClient", coll: Collection, source: list[dict],
                    opts: Options, src_id2name: dict, dst_name2id: dict, dst_id2name: dict,
                    stamp: str) -> tuple[bool, bool]:
    """Converge a replica collection to the source. Returns (changed, drifted).

    *drifted* is True whenever source and replica differed (even in dry-run, when
    nothing is written). *changed* is True only when holesync actually wrote.

    Slow/timed-out writes are tolerated: after applying, the collection is
    re-read and any residual diff is retried once, then verified. This makes the
    sync robust to PH replicas whose writes apply server-side but respond slowly.
    """
    current = client.get_collection(coll.kind)
    to_add, to_update, to_delete = plan_collection(coll, source, current, src_id2name, dst_id2name)
    if not (to_add or to_update or to_delete):
        return False, False

    # Delete/shrink guard — a source glitch must not mass-delete a replica.
    if not opts.force and len(current) > 0:
        if len(to_delete) > len(current) * (opts.max_shrink_pct / 100.0):
            raise SafetyAbort(
                "%s: would delete %d of %d items (> %.0f%%) — refusing without --force"
                % (coll.kind, len(to_delete), len(current), opts.max_shrink_pct)
            )
    # Change cap — a single write triggers a gravity reload on the replica, which
    # is IO-heavy on constrained hardware. Refuse to flood it with a huge bulk
    # apply (e.g. restoring a wiped replica); the operator can --force or rebuild
    # the replica's gravity database directly instead.
    total_changes = len(to_add) + len(to_update) + len(to_delete)
    if not opts.force and total_changes > opts.max_changes:
        raise SafetyAbort(
            "%s: %d changes exceed max_changes=%d — refusing without --force "
            "(a large bulk apply is IO-heavy on the replica)"
            % (coll.kind, total_changes, opts.max_changes)
        )

    LOG.info("[%s] %s drift: +%d ~%d -%d",
             client.name, coll.kind, len(to_add), len(to_update), len(to_delete))
    if opts.dry_run:
        for it in to_add:
            LOG.debug("[%s]   + %s %s", client.name, coll.kind, coll.key(it))
        for it in to_delete:
            LOG.debug("[%s]   - %s %s", client.name, coll.kind, coll.key(it))
        return False, True

    if opts.backup_dir:
        _backup_collection(client.name, coll.kind, current, opts, stamp)

    def apply(items_add, items_upd, items_del):
        for it in items_add:
            m, p, b = coll.create_req(it, _translate_groups(it, src_id2name, dst_name2id))
            client.write_item(m, p, b)
        for it in items_upd:
            m, p, b = coll.update_req(it, _translate_groups(it, src_id2name, dst_name2id))
            client.write_item(m, p, b)
        for it in items_del:
            m, p = coll.delete_req(it)
            client.write_item(m, p, None)

    apply(to_add, to_update, to_delete)

    # Converge: re-read, retry any residual diff once (covers slow/dropped writes).
    current = client.get_collection(coll.kind)
    a2, u2, d2 = plan_collection(coll, source, current, src_id2name, dst_id2name)
    if a2 or u2 or d2:
        LOG.debug("[%s] %s residual after first pass: +%d ~%d -%d; retrying",
                  client.name, coll.kind, len(a2), len(u2), len(d2))
        apply(a2, u2, d2)
        current = client.get_collection(coll.kind)
        a2, u2, d2 = plan_collection(coll, source, current, src_id2name, dst_id2name)

    if a2 or u2 or d2:
        raise ApiError("[%s] %s did not converge (residual +%d ~%d -%d)"
                       % (client.name, coll.kind, len(a2), len(u2), len(d2)))
    return True, True


def group_maps(items: list[dict]) -> tuple[dict, dict]:
    """Return (id->name, name->id) for a /api/groups item list."""
    id2name = {it["id"]: it["name"] for it in items if "id" in it}
    name2id = {it["name"]: it["id"] for it in items if "id" in it}
    return id2name, name2id


# --------------------------------------------------------------------------- #
# Backup / rollback
# --------------------------------------------------------------------------- #
def _backup_collection(name: str, kind: str, items: list[dict], opts: Options, stamp: str) -> None:
    os.makedirs(opts.backup_dir, exist_ok=True)
    path = os.path.join(opts.backup_dir, "%s-%s-%s.json" % (name, kind, stamp))
    with open(path, "w") as fh:
        json.dump(items, fh, indent=2)
    _rotate_backups("%s-%s" % (name, kind), opts)


# --------------------------------------------------------------------------- #
# Backup / rollback (DNS records)
# --------------------------------------------------------------------------- #
def write_backup(name: str, rec: DnsRecords, opts: Options, stamp: str) -> Optional[str]:
    if not opts.backup_dir:
        return None
    os.makedirs(opts.backup_dir, exist_ok=True)
    path = os.path.join(opts.backup_dir, "%s-%s.json" % (name, stamp))
    with open(path, "w") as fh:
        json.dump({"hosts": rec.hosts, "cnameRecords": rec.cnames}, fh, indent=2)
    _rotate_backups(name, opts)
    return path


def _rotate_backups(name: str, opts: Options) -> None:
    if opts.backup_keep <= 0:
        return
    prefix = name + "-"
    files = sorted(
        f for f in os.listdir(opts.backup_dir)
        if f.startswith(prefix) and f.endswith(".json")
    )
    for stale in files[: max(0, len(files) - opts.backup_keep)]:
        try:
            os.remove(os.path.join(opts.backup_dir, stale))
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Per-replica sync
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class Result:
    name: str
    ok: bool
    changed: bool = False
    in_sync: bool = False
    reason: str = ""
    code: int = 0


@dataclasses.dataclass
class SourceState:
    """Everything read once from the source, shared across all replicas."""

    dns: DnsRecords
    groups: list = dataclasses.field(default_factory=list)
    lists: list = dataclasses.field(default_factory=list)
    domains: list = dataclasses.field(default_factory=list)
    group_id2name: dict = dataclasses.field(default_factory=dict)


def validate_source_collections(source: SourceState, opts: Options) -> None:
    """Reject malformed source collection items before any replica write."""
    if opts.sync_groups:
        for g in source.groups:
            if not g.get("name"):
                raise SafetyAbort("source group missing name: %r" % g)
    if opts.sync_adlists:
        for it in source.lists:
            if not it.get("address") or it.get("type") not in ("allow", "block"):
                raise SafetyAbort(
                    "source adlist invalid: %r"
                    % {k: it.get(k) for k in ("address", "type")})
    if opts.sync_domains:
        for it in source.domains:
            if (not it.get("domain") or it.get("type") not in ("allow", "deny")
                    or it.get("kind") not in ("exact", "regex")):
                raise SafetyAbort(
                    "source domain invalid: %r"
                    % {k: it.get(k) for k in ("domain", "type", "kind")})


def _sync_dns_records(client: "PiholeClient", source: DnsRecords, opts: Options,
                      stamp: str, name: str) -> tuple[bool, bool]:
    """Sync dns.hosts + cnameRecords. Returns (changed, drifted)."""
    current = client.get_dns_records()
    if records_equal(source, current, opts):
        sh, sc = current.counts()
        LOG.info("[%s] dns records already in sync (%d hosts, %d cnames)", name, sh, sc)
        return False, False

    shrink_guard(source, current, opts)  # guard before any write
    h_add, h_rem = diff(source.hosts, current.hosts) if opts.sync_hosts else ([], [])
    c_add, c_rem = diff(source.cnames, current.cnames) if opts.sync_cnames else ([], [])
    LOG.info("[%s] dns drift: hosts +%d/-%d, cnames +%d/-%d",
             name, len(h_add), len(h_rem), len(c_add), len(c_rem))
    for e in h_add:
        LOG.debug("[%s]   + host %s", name, e)
    for e in h_rem:
        LOG.debug("[%s]   - host %s", name, e)
    if opts.dry_run:
        LOG.info("[%s] dry-run — not writing dns records", name)
        return False, True

    if opts.backup_dir:
        backup = write_backup(name, current, opts, stamp)
        LOG.info("[%s] dns records backed up -> %s", name, backup)
    client.patch_dns_records(source, opts)

    after = client.get_dns_records()
    if records_equal(source, after, opts):
        LOG.info("[%s] dns records synced", name)
        return True, True

    LOG.error("[%s] dns post-write verification FAILED — rolling back", name)
    client.patch_dns_records(current, opts)
    rolled = records_equal(current, client.get_dns_records(), opts)
    raise ApiError("[%s] dns verify failed; rollback %s"
                   % (name, "succeeded" if rolled else "FAILED"))


def _sync_gravity(client: "PiholeClient", source: SourceState, opts: Options,
                  stamp: str, name: str) -> tuple[bool, bool]:
    """Sync groups, then adlists + domains (group refs remapped by name).
    Triggers a gravity rebuild only when adlists actually changed."""
    changed = drifted = False

    # Groups first so adlist/domain group references resolve on the replica.
    if opts.sync_groups:
        ch, dr = sync_collection(client, GROUPS, source.groups, opts,
                                 source.group_id2name, {}, {}, stamp)
        changed |= ch
        drifted |= dr

    dst_id2name, dst_name2id = group_maps(client.get_collection("groups"))

    adlists_changed = False
    if opts.sync_adlists:
        ch, dr = sync_collection(client, ADLISTS, source.lists, opts,
                                 source.group_id2name, dst_name2id, dst_id2name, stamp)
        changed |= ch
        drifted |= dr
        adlists_changed = ch
    if opts.sync_domains:
        ch, dr = sync_collection(client, DOMAINS, source.domains, opts,
                                 source.group_id2name, dst_name2id, dst_id2name, stamp)
        changed |= ch
        drifted |= dr

    if adlists_changed and opts.run_gravity and not opts.dry_run:
        LOG.info("[%s] adlists changed — rebuilding gravity", name)
        ok = client.run_gravity()
        LOG.info("[%s] gravity rebuild %s", name,
                 "ok" if ok else "did not confirm (continues server-side)")

    if not drifted:
        ng, nl, nd = len(source.groups), len(source.lists), len(source.domains)
        LOG.info("[%s] gravity collections already in sync (%d groups, %d lists, %d domains)",
                 name, ng, nl, nd)
    return changed, drifted


def process_replica(rcfg: ReplicaConfig, source: SourceState, opts: Options, stamp: str) -> Result:
    try:
        client = PiholeClient(rcfg.name, rcfg.url, rcfg.password, opts)
        with client:
            changed = drifted = False
            if opts.sync_hosts or opts.sync_cnames:
                ch, dr = _sync_dns_records(client, source.dns, opts, stamp, rcfg.name)
                changed |= ch
                drifted |= dr
            if opts.sync_gravity:
                ch, dr = _sync_gravity(client, source, opts, stamp, rcfg.name)
                changed |= ch
                drifted |= dr
            return Result(rcfg.name, ok=True, changed=changed, in_sync=not drifted)
    except SafetyAbort as e:
        LOG.error("[%s] safety abort: %s", rcfg.name, e)
        return Result(rcfg.name, ok=False, code=3, reason=str(e))
    except HolesyncError as e:
        # Client-raised errors already carry the "[name]" prefix; don't double it.
        LOG.error("%s", e)
        return Result(rcfg.name, ok=False, code=4 if "verify failed" in str(e) else 1,
                      reason=str(e))


# --------------------------------------------------------------------------- #
# Config / CLI
# --------------------------------------------------------------------------- #
def _read_password(section: configparser.SectionProxy, ctx: str) -> str:
    if section.get("password_file"):
        with open(os.path.expanduser(section["password_file"])) as fh:
            return fh.read().strip()
    pw = section.get("password", "")
    if not pw:
        raise HolesyncError("%s: no password or password_file set" % ctx)
    return pw


def load_config(path: str) -> tuple[ReplicaConfig, list[ReplicaConfig], Options, dict]:
    if not os.path.exists(path):
        raise HolesyncError("config file not found: %s" % path)
    cp = configparser.ConfigParser()
    cp.read(path)

    if not cp.has_section("source"):
        raise HolesyncError("config missing [source] section")
    src = ReplicaConfig(
        name="source",
        url=cp["source"]["url"],
        password=_read_password(cp["source"], "[source]"),
    )

    replicas: list[ReplicaConfig] = []
    for sect in cp.sections():
        if sect == "source" or sect.startswith("replica:") or sect.startswith("replica."):
            if sect == "source":
                continue
            name = sect.split(":", 1)[-1].split(".", 1)[-1]
            replicas.append(ReplicaConfig(
                name=name,
                url=cp[sect]["url"],
                password=_read_password(cp[sect], "[%s]" % sect),
            ))
    if not replicas:
        raise HolesyncError("config defines no [replica:*] sections")

    sy = cp["sync"] if cp.has_section("sync") else {}
    sf = cp["safety"] if cp.has_section("safety") else {}

    def gb(s, k, d):  # get bool
        return s.getboolean(k, d) if hasattr(s, "getboolean") and k in s else d

    def gf(s, k, d):  # get float
        return float(s[k]) if k in s else d

    def gi(s, k, d):  # get int
        return int(s[k]) if k in s else d

    opts = Options(
        sync_hosts=gb(sy, "hosts", True),
        sync_cnames=gb(sy, "cnames", True),
        sync_groups=gb(sy, "groups", False),
        sync_adlists=gb(sy, "adlists", False),
        sync_domains=gb(sy, "domains", False),
        run_gravity=gb(sy, "run_gravity", True),
        timeout=gf(sy, "timeout", 8.0),
        write_timeout=gf(sy, "write_timeout", 30.0),
        gravity_timeout=gf(sy, "gravity_timeout", 180.0),
        retries=gi(sy, "retries", 3),
        verify_tls=gb(sy, "verify_tls", True),
        min_hosts=gi(sf, "min_hosts", 1),
        max_shrink_pct=gf(sf, "max_shrink_pct", 50.0),
        max_changes=gi(sf, "max_changes", 25),
        backup_dir=os.path.expanduser(sf.get("backup_dir", "") if sf else ""),
        backup_keep=gi(sf, "backup_keep", 30),
    )
    # Adlists/domains reference groups; syncing them without groups risks
    # dangling references. Pull groups along automatically.
    if (opts.sync_adlists or opts.sync_domains) and not opts.sync_groups:
        opts.sync_groups = True
    logcfg = dict(cp["log"]) if cp.has_section("log") else {}
    return src, replicas, opts, logcfg


def setup_logging(logcfg: dict, verbose: bool) -> None:
    level = logging.DEBUG if verbose else getattr(
        logging, str(logcfg.get("level", "info")).upper(), logging.INFO
    )
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if logcfg.get("file"):
        try:
            handlers.append(logging.FileHandler(os.path.expanduser(logcfg["file"])))
        except OSError as e:
            print("warning: cannot open log file: %s" % e, file=sys.stderr)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        handlers=handlers,
    )


def acquire_lock(path: str):
    fh = open(path, "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return None
    fh.write(str(os.getpid()))
    fh.flush()
    return fh


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="holesync",
        description="Replicate Pi-hole v6 local DNS records to one or more replicas.",
    )
    ap.add_argument("-c", "--config", default="/etc/holesync/holesync.conf",
                    help="path to config file (default: %(default)s)")
    ap.add_argument("-n", "--dry-run", action="store_true",
                    help="show what would change without writing")
    ap.add_argument("--check", action="store_true",
                    help="read-only drift check; exit 10 if any replica is out of sync")
    ap.add_argument("--force", action="store_true",
                    help="bypass the drastic-shrink guard")
    ap.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    ap.add_argument("-V", "--version", action="version", version="holesync " + __version__)
    args = ap.parse_args(argv)

    try:
        src_cfg, replicas, opts, logcfg = load_config(args.config)
    except HolesyncError as e:
        print("config error: %s" % e, file=sys.stderr)
        return 2

    opts.dry_run = args.dry_run or args.check
    opts.force = args.force
    setup_logging(logcfg, args.verbose)

    lock_path = logcfg.get("lockfile", "/tmp/holesync.lock")
    lock = acquire_lock(lock_path)
    if lock is None:
        LOG.warning("another holesync run holds %s — exiting", lock_path)
        return 5

    stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    try:
        LOG.info("holesync %s starting (source=%s, replicas=%d%s)",
                 __version__, src_cfg.url, len(replicas),
                 ", check-only" if args.check else ", dry-run" if args.dry_run else "")
        # Read the source ONCE; validate before touching any replica.
        with PiholeClient(src_cfg.name, src_cfg.url, src_cfg.password, opts) as sc:
            source = SourceState(dns=sc.get_dns_records())
            if opts.sync_groups:
                source.groups = sc.get_collection("groups")
                source.group_id2name, _ = group_maps(source.groups)
            if opts.sync_adlists:
                source.lists = sc.get_collection("lists")
            if opts.sync_domains:
                source.domains = sc.get_collection("domains")
        sh, scn = source.dns.counts()
        LOG.info("source: %d hosts, %d cnames, %d groups, %d adlists, %d domains",
                 sh, scn, len(source.groups), len(source.lists), len(source.domains))
        validate_source(source.dns, opts)
        validate_source_collections(source, opts)

        results = [process_replica(r, source, opts, stamp) for r in replicas]
    except HolesyncError as e:
        LOG.error("%s", e)
        return 1
    finally:
        try:
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()
            os.unlink(lock_path)
        except OSError:
            pass

    failures = [r for r in results if not r.ok]
    changed = [r for r in results if r.changed]
    drifted = [r for r in results if (not r.in_sync) and r.ok]

    if args.check:
        if drifted:
            LOG.warning("drift: %s", ", ".join(r.name for r in drifted))
            return 10
        LOG.info("all replicas in sync")
        return 0

    if failures:
        return max(r.code for r in failures)
    LOG.info("done: %d replica(s), %d changed, %d already in sync",
             len(results), len(changed), len(results) - len(changed))
    return 0


if __name__ == "__main__":
    sys.exit(main())

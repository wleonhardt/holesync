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
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

__version__ = "1.5.0"

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
    sync_clients: bool = False
    # Extra config-layer keys to mirror (dotted paths, e.g. "dhcp.hosts" for
    # static DHCP leases). Same zero-downtime PATCH mechanism as dns.hosts.
    config_keys: tuple = ()
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
    shrink_min: int = 5                # shrink guard ignores removals of <= this many items
    max_changes: int = 100             # per-collection change cap; over this, abort (use --force)
    load_probe_max: float = 5.0        # if a cheap GET is slower than this, defer collection writes
    backup_dir: str = ""
    backup_keep: int = 30
    dry_run: bool = False
    force: bool = False

    @property
    def sync_gravity(self) -> bool:
        """True if any gravity-database collection is enabled."""
        return (self.sync_groups or self.sync_adlists
                or self.sync_domains or self.sync_clients)


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

    Removals of up to ``shrink_min`` records are always allowed — the guard
    targets mass-deletion, not ordinary edits to a small record set.
    """
    if opts.force:
        return
    threshold = 1.0 - (opts.max_shrink_pct / 100.0)

    def check(label: str, src_n: int, dst_n: int) -> None:
        drop = dst_n - src_n
        if drop > opts.shrink_min and src_n < dst_n * threshold:
            raise SafetyAbort(
                "%s would drop %d -> %d (> %.0f%% shrink) — refusing without --force"
                % (label, dst_n, src_n, opts.max_shrink_pct)
            )

    if opts.sync_hosts:
        check("host records", len(src.hosts), len(dst.hosts))
    if opts.sync_cnames:
        check("cname records", len(src.cnames), len(dst.cnames))


# --------------------------------------------------------------------------- #
# Extra config-layer keys (config_keys option)
# --------------------------------------------------------------------------- #
def walk_config(cfg: dict, path: str):
    """Follow a dotted path into a nested config dict; None if absent."""
    cur = cfg
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def nest_config(path: str, value) -> dict:
    """Inverse of walk_config: ('a.b.c', v) -> {'a': {'b': {'c': v}}}."""
    for part in reversed(path.split(".")):
        value = {part: value}
    return value


def merge_config(dst: dict, src: dict) -> dict:
    """Recursively merge src into dst, so several keys share one PATCH."""
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            merge_config(dst[k], v)
        else:
            dst[k] = v
    return dst


_CONFIG_KEY_RE = re.compile(r"^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$")


def parse_config_keys(raw: str) -> tuple:
    """Validate the config_keys option: dotted paths, comma/space separated.

    Rejects keys holesync already owns, and everything under webserver.* —
    that subtree holds API credentials/ports, and pushing the source's values
    would cut holesync (and the user) off from the replica."""
    keys = tuple(k for k in re.split(r"[,\s]+", raw) if k)
    for k in keys:
        if not _CONFIG_KEY_RE.match(k):
            raise HolesyncError("config_keys: invalid key %r" % k)
        if k in ("dns.hosts", "dns.cnameRecords"):
            raise HolesyncError(
                "config_keys: %r is already synced by the hosts/cnames options" % k)
        if k == "webserver" or k.startswith("webserver."):
            raise HolesyncError(
                "config_keys: refusing %r — webserver settings include API "
                "credentials and can lock holesync out of the replica" % k)
    return keys


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

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self._ctx = ctx

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
            # Single attempt: logout is best-effort (the session expires on its
            # own) and retrying against a server that just died only adds
            # seconds of backoff to an already-failing run.
            self._request("DELETE", "/api/auth", max_attempts=1)
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
        self.patch_config({"dns": dns})

    def get_config(self) -> dict:
        """The full config tree (for the extra config_keys sync)."""
        status, payload = self._request("GET", "/api/config")
        if status != 200:
            raise ApiError("[%s] GET /api/config -> %s" % (self.name, status))
        return payload.get("config") or {}

    def patch_config(self, subtree: dict) -> None:
        status, payload = self._request("PATCH", "/api/config", {"config": subtree})
        if status not in (200, 201):
            err = (payload or {}).get("error", {})
            raise ApiError(
                "[%s] PATCH /api/config -> %s: %s"
                % (self.name, status, err.get("message") or err or payload)
            )

    def get_version(self) -> str:
        """This Pi-hole's FTL version string (e.g. 'v6.6'); '' if unavailable."""
        try:
            status, payload = self._request("GET", "/api/info/version", max_attempts=1)
        except HolesyncError:
            return ""
        if status != 200:
            return ""
        ftl = (payload.get("version") or {}).get("ftl") or {}
        return str((ftl.get("local") or {}).get("version") or "")

    # -- gravity-database collections --------------------------------------- #
    def get_collection(self, kind: str) -> list[dict]:
        """kind ∈ {groups, lists, domains}. Returns the raw item list.

        Uses the longer write timeout: a collection read can immediately follow a
        write, and the replica may still be holding its database lock during the
        post-write list reload — the GET must wait that out rather than fail."""
        path = {"groups": "/api/groups", "lists": "/api/lists",
                "domains": "/api/domains", "clients": "/api/clients"}[kind]
        status, payload = self._request("GET", path, timeout=self.opts.write_timeout)
        if status != 200:
            raise ApiError("[%s] GET %s -> %s" % (self.name, path, status))
        return list(payload.get(kind) or [])

    def write_item(self, method: str, path: str, body) -> tuple[int, dict]:
        """A collection mutation. These trigger a synchronous FTL list reload on
        the server, so they can be slow to respond — use the longer write timeout
        and a SINGLE attempt. A slow write often applies server-side even when the
        HTTP response times out; retrying at this layer would multiply the wait
        and risk overlapping reloads, so we tolerate the timeout and let the
        caller's read-back/converge step decide whether the change actually
        landed."""
        try:
            status, payload = self._request(method, path, body,
                                            timeout=self.opts.write_timeout, max_attempts=1)
        except HolesyncError:
            return 0, {}
        # status 0 == timeout, tolerated by design (the write may still apply).
        # Any real non-2xx is a rejection (e.g. a bad regex, 4xx) that the
        # converge step would otherwise report only as an opaque "did not
        # converge" — surface it here with the server's own message. (2xx spans
        # 200/201 for adds/updates and 204 for :batchDelete.)
        if status and not (200 <= status < 300):
            err = (payload or {}).get("error", {})
            LOG.warning("[%s] %s %s -> %s: %s", self.name, method, path, status,
                        err.get("message") or err or payload)
        return status, payload

    def batch_delete(self, kind: str, keys: list) -> None:
        """Delete many items in one call via /api/<kind>:batchDelete."""
        self.write_item("POST", "/api/%s:batchDelete" % kind, keys)

    def get_messages(self) -> list:
        """FTL's diagnostic messages — where it reports DB corruption, regex
        errors, etc. Used as a replica health signal. Best-effort: returns []."""
        try:
            status, payload = self._request("GET", "/api/info/messages")
            return list(payload.get("messages") or []) if status == 200 else []
        except HolesyncError:
            return []

    def probe(self) -> float:
        """Round-trip seconds for a cheap GET — a load/liveness signal. Returns
        +inf if it fails or exceeds the probe budget (i.e. the replica is busy)."""
        budget = self.opts.load_probe_max
        start = time.monotonic()
        try:
            status, _ = self._request("GET", "/api/info/messages",
                                      timeout=budget, max_attempts=1)
        except HolesyncError:
            return float("inf")
        return (time.monotonic() - start) if status == 200 else float("inf")

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
    """Adapter describing how to read/compare/write one gravity collection.

    Writes are batched: items that share a destination + attributes are created
    in a single array POST, and deletions go through the `:batchDelete` endpoint
    — so a whole-collection sync costs a few list-reloads on the replica rather
    than one per item.
    """

    kind: str                                   # groups | lists | domains | clients
    key: "callable"                             # item -> hashable identity (for diffing)
    scalar_fields: tuple                        # compared fields besides the key + groups
    has_groups: bool                            # references groups by id?
    item_field: str                             # the per-item field name in an add payload
    add_path: "callable"                        # (item) -> POST path for adding it
    add_attrs: "callable"                       # (item, gids) -> shared attrs (no item_field)
    update_req: "callable"                      # (item, gids) -> (method, path, body)
    delete_key: "callable"                      # (item) -> dict for the :batchDelete body
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
    item_field="name",
    add_path=lambda it: "/api/groups",
    add_attrs=lambda it, g: {"comment": it.get("comment") or "", "enabled": bool(it["enabled"])},
    update_req=lambda it, g: ("PUT", "/api/groups/" + _q(it["name"]),
                              {"name": it["name"], "comment": it.get("comment") or "",
                               "enabled": bool(it["enabled"])}),
    delete_key=lambda it: {"item": it["name"]},
    protect=lambda it: it.get("name") == "Default" or it.get("id") == 0,
)

ADLISTS = Collection(
    kind="lists",
    key=lambda it: (it["type"], it["address"]),
    scalar_fields=("enabled", "comment"),
    has_groups=True,
    item_field="address",
    add_path=lambda it: "/api/lists?type=" + _q(it["type"]),
    add_attrs=lambda it, g: {"comment": it.get("comment") or "", "enabled": bool(it["enabled"]), "groups": g},
    update_req=lambda it, g: ("PUT", "/api/lists/" + _q(it["address"]) + "?type=" + _q(it["type"]),
                              {"comment": it.get("comment") or "",
                               "enabled": bool(it["enabled"]), "groups": g}),
    delete_key=lambda it: {"item": it["address"], "type": it["type"]},
)

DOMAINS = Collection(
    kind="domains",
    key=lambda it: (it["type"], it["kind"], it["domain"]),
    scalar_fields=("enabled", "comment"),
    has_groups=True,
    item_field="domain",
    add_path=lambda it: "/api/domains/%s/%s" % (_q(it["type"]), _q(it["kind"])),
    add_attrs=lambda it, g: {"comment": it.get("comment") or "", "enabled": bool(it["enabled"]), "groups": g},
    update_req=lambda it, g: ("PUT", "/api/domains/%s/%s/%s" % (_q(it["type"]), _q(it["kind"]), _q(it["domain"])),
                              {"comment": it.get("comment") or "",
                               "enabled": bool(it["enabled"]), "groups": g}),
    delete_key=lambda it: {"item": it["domain"], "type": it["type"], "kind": it["kind"]},
)

CLIENTS = Collection(
    kind="clients",
    key=lambda it: it["client"],          # an IP, MAC, hostname, or subnet
    scalar_fields=("comment",),           # clients have no 'enabled' field
    has_groups=True,
    item_field="client",
    add_path=lambda it: "/api/clients",
    add_attrs=lambda it, g: {"comment": it.get("comment") or "", "groups": g},
    update_req=lambda it, g: ("PUT", "/api/clients/" + _q(it["client"]),
                              {"comment": it.get("comment") or "", "groups": g}),
    delete_key=lambda it: {"item": it["client"]},
)


def bucket_adds(coll: Collection, items: list[dict], gids_fn) -> list:
    """Group items to add into the fewest array-POSTs: items sharing a path and
    attributes (comment/enabled/groups) ride in one request. Returns a list of
    (path, body) where body carries the item_field as an array."""
    buckets: dict = {}
    for it in items:
        attrs = coll.add_attrs(it, gids_fn(it))
        path = coll.add_path(it)
        sig = (path, json.dumps(attrs, sort_keys=True))
        buckets.setdefault(sig, (path, attrs, []))[2].append(it[coll.item_field])
    return [(path, {**attrs, coll.item_field: vals})
            for path, attrs, vals in buckets.values()]


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
    # Removals of up to shrink_min items are always allowed (normal edits to a
    # small collection); the guard targets mass-deletion of a large one.
    if not opts.force and len(current) > 0:
        if (len(to_delete) > opts.shrink_min
                and len(to_delete) > len(current) * (opts.max_shrink_pct / 100.0)):
            raise SafetyAbort(
                "%s: would delete %d of %d items (> %.0f%%) — refusing without --force"
                % (coll.kind, len(to_delete), len(current), opts.max_shrink_pct)
            )
    # Change cap — a sanity bound on how much one run will rewrite. Writes are
    # batched (few reloads even for many items), so this is mostly a guard against
    # a pathological diff, not an IO limit. Override a legitimate bulk with --force.
    total_changes = len(to_add) + len(to_update) + len(to_delete)
    if not opts.force and total_changes > opts.max_changes:
        raise SafetyAbort(
            "%s: %d changes exceed max_changes=%d — refusing without --force"
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

    def gids(it):
        return _translate_groups(it, src_id2name, dst_name2id) if coll.has_groups else []

    def apply(items_add, items_upd, items_del):
        # Deletes: one :batchDelete call for the whole collection.
        if items_del:
            client.batch_delete(coll.kind, [coll.delete_key(it) for it in items_del])
        # Adds: one array POST per shared-attribute group (one reload, not N).
        for path, body in bucket_adds(coll, items_add, gids):
            client.write_item("POST", path, body)
        # Updates change attributes per item, so they stay individual (rare).
        for it in items_upd:
            m, p, b = coll.update_req(it, gids(it))
            client.write_item(m, p, b)

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


_DB_TROUBLE = ("malformed", "corrupt", "disk image", "database is locked",
               "no such table", "database error")


def db_health_messages(client: "PiholeClient") -> list:
    """FTL diagnostic messages that indicate a gravity-database problem.

    The gravity collections all live in gravity.db; before writing to a replica
    we check it isn't already reporting corruption, and after writing we check we
    didn't introduce one. Matches on message type or text so it stays robust
    across FTL versions."""
    out = []
    for m in client.get_messages():
        typ = str(m.get("type", "")).upper()
        text = str(m.get("message", "")).lower()
        if "DATABASE" in typ or "GRAVITY" in typ or any(w in text for w in _DB_TROUBLE):
            out.append(m)
    return out


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


_STAMP_RE = r"\d{8}T\d{6}"


def _rotate_backups(base: str, opts: Options) -> None:
    """Trim backups for one series to backup_keep.

    ``base`` is the filename stem: the replica name for DNS backups
    (``name-<stamp>.json``) or ``name-<kind>`` for a collection
    (``name-kind-<stamp>.json``). Matching an EXACT ``base-<stamp>.json``
    keeps the series separate — otherwise the DNS series' ``name-`` prefix also
    matches ``name-domains-…`` and the two pools evict each other."""
    if opts.backup_keep <= 0:
        return
    pat = re.compile(r"^%s-%s\.json$" % (re.escape(base), _STAMP_RE))
    files = sorted(f for f in os.listdir(opts.backup_dir) if pat.match(f))
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
    clients: list = dataclasses.field(default_factory=list)
    group_id2name: dict = dataclasses.field(default_factory=dict)
    config_extra: dict = dataclasses.field(default_factory=dict)  # key -> value
    ftl_version: str = ""


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
    if opts.sync_clients:
        for it in source.clients:
            if not it.get("client"):
                raise SafetyAbort("source client missing identifier: %r" % it)


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


def _sync_config_extra(client: "PiholeClient", source: SourceState, opts: Options,
                       stamp: str, name: str) -> tuple[bool, bool]:
    """Sync the extra config_keys. Returns (changed, drifted).

    Same discipline as DNS records — diff-gate, shrink-guard list values, back
    up the replica's old values, one PATCH for all drifted keys, verify by
    read-back, roll back on a failed verification."""
    cfg = client.get_config()
    to_write: dict = {}
    old: dict = {}
    for key, sval in source.config_extra.items():
        rval = walk_config(cfg, key)
        if sval == rval:
            continue
        if isinstance(sval, list) and isinstance(rval, list) and not opts.force:
            drop = len(rval) - len(sval)
            if (drop > opts.shrink_min
                    and len(sval) < len(rval) * (1.0 - opts.max_shrink_pct / 100.0)):
                raise SafetyAbort(
                    "config %s would drop %d -> %d entries (> %.0f%% shrink) — "
                    "refusing without --force"
                    % (key, len(rval), len(sval), opts.max_shrink_pct))
        to_write[key] = sval
        old[key] = rval
    if not to_write:
        LOG.info("[%s] config keys already in sync (%s)",
                 name, ", ".join(sorted(source.config_extra)))
        return False, False

    LOG.info("[%s] config drift: %s", name, ", ".join(sorted(to_write)))
    if opts.dry_run:
        return False, True
    if opts.backup_dir:
        _backup_collection(name, "config", old, opts, stamp)

    tree: dict = {}
    for key, val in to_write.items():
        merge_config(tree, nest_config(key, val))
    client.patch_config(tree)

    after = client.get_config()
    bad = sorted(k for k, v in to_write.items() if walk_config(after, k) != v)
    if not bad:
        LOG.info("[%s] config keys synced: %s", name, ", ".join(sorted(to_write)))
        return True, True

    LOG.error("[%s] config verify FAILED for %s — rolling back", name, ", ".join(bad))
    tree = {}
    for key, val in old.items():
        if val is not None:   # a key absent on the replica can't be un-set via PATCH
            merge_config(tree, nest_config(key, val))
    if tree:
        client.patch_config(tree)
    raise ApiError("[%s] config verify failed for %s; rollback attempted"
                   % (name, ", ".join(bad)))


def _sync_gravity(client: "PiholeClient", source: SourceState, opts: Options,
                  stamp: str, name: str) -> tuple[bool, bool]:
    """Sync groups, then adlists + domains (group refs remapped by name).
    Triggers a gravity rebuild only when adlists actually changed."""
    changed = drifted = False

    # Pre-flight: never write into a replica whose gravity database is already
    # reporting trouble — that is how a bad state gets amplified.
    pre = db_health_messages(client)
    if pre and not opts.dry_run and not opts.force:
        raise SafetyAbort(
            "replica reports a gravity-database problem (%s) — refusing to write "
            "(repair the replica, or pass --force): %r"
            % (len(pre), pre[0].get("message")))

    # Load pre-flight: each collection write triggers a list reload that is
    # IO-heavy on constrained replicas. If the replica is already slow to answer
    # a trivial request, DON'T pile writes onto it — defer to a later run when it
    # is idle. (DNS-record sync, which is light, has already run.)
    if not opts.dry_run and not opts.force:
        rtt = client.probe()
        if rtt > opts.load_probe_max:
            LOG.warning("[%s] replica slow to respond (%.1fs > %.1fs) — deferring "
                        "gravity-collection writes to a later run",
                        name, rtt, opts.load_probe_max)
            return False, False

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
    if opts.sync_clients:
        ch, dr = sync_collection(client, CLIENTS, source.clients, opts,
                                 source.group_id2name, dst_name2id, dst_id2name, stamp)
        changed |= ch
        drifted |= dr

    if adlists_changed and opts.run_gravity and not opts.dry_run:
        LOG.info("[%s] adlists changed — rebuilding gravity", name)
        ok = client.run_gravity()
        LOG.info("[%s] gravity rebuild %s", name,
                 "ok" if ok else "did not confirm (continues server-side)")

    # Post-flight: if we wrote and a NEW database problem appeared, fail loudly —
    # it points at a write that the replica could not digest cleanly.
    if changed and not opts.dry_run:
        new = [m for m in db_health_messages(client) if m not in pre]
        if new:
            raise ApiError(
                "[%s] replica reported a database problem after sync (%s) — "
                "check gravity.db health" % (name, new[0].get("message")))

    if not drifted:
        LOG.info("[%s] gravity collections already in sync "
                 "(%d groups, %d lists, %d domains, %d clients)", name,
                 len(source.groups), len(source.lists),
                 len(source.domains), len(source.clients))
    return changed, drifted


def check_exit_code(results: list) -> int:
    """Exit code for --check mode. A replica that could not be evaluated
    (unreachable, auth failure, guard abort) DOMINATES a plain drift result:
    reporting "in sync" when a replica never answered would defeat the check."""
    failures = [r for r in results if not r.ok]
    if failures:
        return max(r.code for r in failures)
    if any(not r.in_sync for r in results):
        return 10
    return 0


def process_replica(rcfg: ReplicaConfig, source: SourceState, opts: Options, stamp: str) -> Result:
    try:
        client = PiholeClient(rcfg.name, rcfg.url, rcfg.password, opts)
        with client:
            changed = drifted = False
            ver = client.get_version()
            if ver and source.ftl_version and ver != source.ftl_version:
                LOG.warning("[%s] FTL %s differs from source FTL %s — sync should "
                            "work, but keep Pi-hole versions aligned",
                            rcfg.name, ver, source.ftl_version)
            if opts.sync_hosts or opts.sync_cnames:
                ch, dr = _sync_dns_records(client, source.dns, opts, stamp, rcfg.name)
                changed |= ch
                drifted |= dr
            if opts.config_keys:
                ch, dr = _sync_config_extra(client, source, opts, stamp, rcfg.name)
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
    except Exception as e:  # noqa: BLE001 — isolate: one bad replica must not
        # abort the others (e.g. a KeyError from a malformed replica-side item).
        LOG.exception("[%s] unexpected error", rcfg.name)
        return Result(rcfg.name, ok=False, code=1, reason=str(e))


# --------------------------------------------------------------------------- #
# Config / CLI
# --------------------------------------------------------------------------- #
def _read_password(section: configparser.SectionProxy, ctx: str) -> str:
    if section.get("password_file"):
        try:
            with open(os.path.expanduser(section["password_file"])) as fh:
                return fh.read().strip()
        except OSError as e:
            raise HolesyncError("%s: cannot read password_file: %s" % (ctx, e))
    pw = section.get("password", "")
    if not pw:
        raise HolesyncError("%s: no password or password_file set" % ctx)
    return pw


def load_config(path: str) -> tuple[ReplicaConfig, list[ReplicaConfig], Options, dict]:
    if not os.path.exists(path):
        raise HolesyncError("config file not found: %s" % path)
    # interpolation=None: passwords may contain a literal '%'.
    # inline_comment_prefixes: allow the ';'/'#' inline comments used throughout
    # holesync.conf.example (default ConfigParser would fold them into the value).
    cp = configparser.ConfigParser(
        interpolation=None, inline_comment_prefixes=(";", "#"))
    # read_file, not read(): read() silently ignores unreadable files, which
    # turns a permissions problem into a baffling "missing [source]" error.
    try:
        with open(path) as fh:
            cp.read_file(fh)
    except OSError as e:
        raise HolesyncError("cannot read %s: %s" % (path, e))
    except configparser.Error as e:
        raise HolesyncError("cannot parse %s: %s" % (path, e))

    def require_url(sect: str) -> str:
        try:
            return cp[sect]["url"]
        except KeyError:
            raise HolesyncError("[%s]: missing required 'url'" % sect)

    if not cp.has_section("source"):
        raise HolesyncError("config missing [source] section")
    src = ReplicaConfig(
        name="source",
        url=require_url("source"),
        password=_read_password(cp["source"], "[source]"),
    )

    known = {"source", "sync", "safety", "log"}
    replicas: list[ReplicaConfig] = []
    for sect in cp.sections():
        if sect in known:
            continue
        if sect.startswith("replica:") or sect.startswith("replica."):
            name = sect[len("replica:"):]  # strip prefix once; keep dots in name
            if not name:
                raise HolesyncError("[%s]: replica name must not be empty" % sect)
            replicas.append(ReplicaConfig(
                name=name,
                url=require_url(sect),
                password=_read_password(cp[sect], "[%s]" % sect),
            ))
        else:
            raise HolesyncError(
                "unrecognized config section [%s] (expected [source], [sync], "
                "[safety], [log], or [replica:<name>])" % sect)
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

    try:
        opts = Options(
            sync_hosts=gb(sy, "hosts", True),
            sync_cnames=gb(sy, "cnames", True),
            sync_groups=gb(sy, "groups", False),
            sync_adlists=gb(sy, "adlists", False),
            sync_domains=gb(sy, "domains", False),
            sync_clients=gb(sy, "clients", False),
            run_gravity=gb(sy, "run_gravity", False),
            timeout=gf(sy, "timeout", 8.0),
            write_timeout=gf(sy, "write_timeout", 30.0),
            gravity_timeout=gf(sy, "gravity_timeout", 180.0),
            retries=gi(sy, "retries", 3),
            verify_tls=gb(sy, "verify_tls", True),
            min_hosts=gi(sf, "min_hosts", 1),
            max_shrink_pct=gf(sf, "max_shrink_pct", 50.0),
            shrink_min=gi(sf, "shrink_min", 5),
            max_changes=gi(sf, "max_changes", 100),
            load_probe_max=gf(sf, "load_probe_max", 5.0),
            backup_dir=os.path.expanduser(sf.get("backup_dir", "") if sf else ""),
            backup_keep=gi(sf, "backup_keep", 30),
            config_keys=parse_config_keys(sy.get("config_keys", "") if sy else ""),
        )
    except ValueError as e:
        raise HolesyncError("invalid value in [sync]/[safety]: %s" % e)
    # Adlists/domains/clients reference groups; syncing them without groups
    # risks dangling references. Pull groups along automatically.
    if (opts.sync_adlists or opts.sync_domains or opts.sync_clients) and not opts.sync_groups:
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


def default_lock_path() -> str:
    """Root gets /run/holesync (matches the systemd unit's RuntimeDirectory=);
    unprivileged runs get a per-user runtime dir they can actually write, so the
    default never triggers the noisy permission-fallback in acquire_lock."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return "/run/holesync/holesync.lock"
    base = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    return os.path.join(base, "holesync.lock")


def acquire_lock(path: str):
    """Take an exclusive advisory lock. Returns the open handle, or None if
    another run already holds it. Opens without truncating (so a failed attempt
    can't clobber the holder's PID) and never unlinks the file (unlink-then-
    recreate is the classic flock race that lets two runs both 'hold' it)."""
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fh = open(path, "a+")
    except OSError as e:
        fallback = os.path.join(tempfile.gettempdir(), "holesync.lock")
        LOG.warning("lockfile %s unavailable (%s) — falling back to %s",
                    path, e, fallback)
        fh = open(fallback, "a+")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    fh.seek(0)
    fh.truncate()
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
    ap.add_argument("-r", "--replica", action="append", metavar="NAME",
                    help="limit this run to the named replica (repeatable)")
    ap.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    ap.add_argument("-V", "--version", action="version", version="holesync " + __version__)
    args = ap.parse_args(argv)

    try:
        src_cfg, replicas, opts, logcfg = load_config(args.config)
    except HolesyncError as e:
        print("config error: %s" % e, file=sys.stderr)
        return 2

    if args.replica:
        byname = {r.name: r for r in replicas}
        unknown = [n for n in args.replica if n not in byname]
        if unknown:
            print("config error: unknown replica(s): %s (known: %s)"
                  % (", ".join(unknown), ", ".join(sorted(byname))), file=sys.stderr)
            return 2
        replicas = [byname[n] for n in args.replica]

    opts.dry_run = args.dry_run or args.check
    opts.force = args.force
    setup_logging(logcfg, args.verbose)

    # Default outside /tmp: systemd PrivateTmp=true gives the unit a private
    # /tmp, so a /tmp lock can't exclude a manual CLI run. /run/holesync is
    # created by the unit's RuntimeDirectory= (and by acquire_lock otherwise).
    lock_path = logcfg.get("lockfile") or default_lock_path()
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
            source.ftl_version = sc.get_version()
            if source.ftl_version:
                LOG.info("source FTL %s", source.ftl_version)
            if opts.config_keys:
                cfg = sc.get_config()
                for key in opts.config_keys:
                    val = walk_config(cfg, key)
                    if val is None:
                        raise HolesyncError(
                            "source config has no key %r (check config_keys)" % key)
                    source.config_extra[key] = val
            if opts.sync_groups:
                source.groups = sc.get_collection("groups")
                source.group_id2name, _ = group_maps(source.groups)
            if opts.sync_adlists:
                source.lists = sc.get_collection("lists")
            if opts.sync_domains:
                source.domains = sc.get_collection("domains")
            if opts.sync_clients:
                source.clients = sc.get_collection("clients")
        sh, scn = source.dns.counts()
        LOG.info("source: %d hosts, %d cnames, %d groups, %d adlists, %d domains, %d clients",
                 sh, scn, len(source.groups), len(source.lists),
                 len(source.domains), len(source.clients))
        validate_source(source.dns, opts)
        validate_source_collections(source, opts)

        results = [process_replica(r, source, opts, stamp) for r in replicas]
    except HolesyncError as e:
        LOG.error("%s", e)
        return 1
    except Exception:  # noqa: BLE001 — e.g. a malformed SOURCE-side item
        # (replica-side garbage is isolated in process_replica, but the source
        # read happens here). Keep the exit-code contract instead of a traceback.
        LOG.exception("unexpected error")
        return 1
    finally:
        # Closing the fd releases the flock. Deliberately do NOT unlink the
        # lockfile — unlink-then-recreate races let two runs both acquire it.
        try:
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()
        except OSError:
            pass

    failures = [r for r in results if not r.ok]
    changed = [r for r in results if r.changed]
    drifted = [r for r in results if (not r.in_sync) and r.ok]

    if args.check:
        if failures:
            LOG.error("check: %d replica(s) could not be evaluated: %s",
                      len(failures), ", ".join(r.name for r in failures))
        elif drifted:
            LOG.warning("drift: %s", ", ".join(r.name for r in drifted))
        else:
            LOG.info("all replicas in sync")
        return check_exit_code(results)

    if failures:
        return max(r.code for r in failures)
    LOG.info("done: %d replica(s), %d changed, %d already in sync",
             len(results), len(changed), len(results) - len(changed))
    return 0


if __name__ == "__main__":
    sys.exit(main())

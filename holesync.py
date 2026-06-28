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

__version__ = "1.0.0"

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
    timeout: float = 8.0
    retries: int = 3
    verify_tls: bool = True
    min_hosts: int = 1
    max_shrink_pct: float = 50.0
    backup_dir: str = ""
    backup_keep: int = 30
    dry_run: bool = False
    force: bool = False


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
    def _raw(self, method: str, path: str, body: Optional[dict]):
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
            with urllib.request.urlopen(req, timeout=self.opts.timeout, context=self._ctx) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> tuple[int, dict]:
        """Send a request, retrying transient failures with backoff."""
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.opts.retries + 1):
            try:
                status, raw = self._raw(method, path, body)
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
            if attempt < self.opts.retries:
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


# --------------------------------------------------------------------------- #
# Backup / rollback
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


def process_replica(rcfg: ReplicaConfig, source: DnsRecords, opts: Options, stamp: str) -> Result:
    try:
        client = PiholeClient(rcfg.name, rcfg.url, rcfg.password, opts)
        with client:
            current = client.get_dns_records()

            if records_equal(source, current, opts):
                sh, sc = current.counts()
                LOG.info("[%s] already in sync (%d hosts, %d cnames) — no change", rcfg.name, sh, sc)
                return Result(rcfg.name, ok=True, in_sync=True)

            # Guardrails before any write.
            shrink_guard(source, current, opts)

            h_add, h_rem = diff(source.hosts, current.hosts) if opts.sync_hosts else ([], [])
            c_add, c_rem = diff(source.cnames, current.cnames) if opts.sync_cnames else ([], [])
            LOG.info(
                "[%s] drift detected: hosts +%d/-%d, cnames +%d/-%d",
                rcfg.name, len(h_add), len(h_rem), len(c_add), len(c_rem),
            )
            for e in h_add:
                LOG.debug("[%s]   + host %s", rcfg.name, e)
            for e in h_rem:
                LOG.debug("[%s]   - host %s", rcfg.name, e)

            if opts.dry_run:
                LOG.info("[%s] dry-run — not writing", rcfg.name)
                return Result(rcfg.name, ok=True, changed=False)

            backup = write_backup(rcfg.name, current, opts, stamp)
            if backup:
                LOG.info("[%s] replica state backed up -> %s", rcfg.name, backup)

            client.patch_dns_records(source, opts)

            after = client.get_dns_records()
            if records_equal(source, after, opts):
                LOG.info("[%s] sync OK — replica now matches source", rcfg.name)
                return Result(rcfg.name, ok=True, changed=True)

            # Verification failed: undo.
            LOG.error("[%s] post-write verification FAILED — rolling back", rcfg.name)
            client.patch_dns_records(current, opts)
            rolled = records_equal(current, client.get_dns_records(), opts)
            return Result(
                rcfg.name, ok=False, code=4,
                reason="verify failed; rollback %s" % ("succeeded" if rolled else "FAILED"),
            )
    except SafetyAbort as e:
        LOG.error("[%s] safety abort: %s", rcfg.name, e)
        return Result(rcfg.name, ok=False, code=3, reason=str(e))
    except HolesyncError as e:
        # Client-raised errors already carry the "[name]" prefix; don't double it.
        LOG.error("%s", e)
        return Result(rcfg.name, ok=False, code=1, reason=str(e))


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
        timeout=gf(sy, "timeout", 8.0),
        retries=gi(sy, "retries", 3),
        verify_tls=gb(sy, "verify_tls", True),
        min_hosts=gi(sf, "min_hosts", 1),
        max_shrink_pct=gf(sf, "max_shrink_pct", 50.0),
        backup_dir=os.path.expanduser(sf.get("backup_dir", "") if sf else ""),
        backup_keep=gi(sf, "backup_keep", 30),
    )
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
            source = sc.get_dns_records()
        sh, scn = source.counts()
        LOG.info("source has %d host records, %d cname records", sh, scn)
        validate_source(source, opts)

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

# holesync

**The boring way to keep your Pi-holes in sync.**

Boring is the point: no daemon, no dependencies, no Docker, no drama — one
Python file, run by cron, that copies your hand-maintained Pi-hole v6 config
from a primary to your replicas and refuses to do anything reckless along the
way.

> Most sync tools are exciting right up until they empty your DNS records.
> holesync is designed to never be exciting.

```
┌──────────────┐    read once, validate    ┌──────────────┐
│  Pi-hole #1  │ ────────────────────────► │   holesync   │
│  (source)    │                           │  (cron job)  │
└──────────────┘                           └──────┬───────┘
                                                  │ diff → backup → write → verify
                                                  │ (or, usually: "in sync, bye")
                                                  ▼
                                     ┌──────────────┐  ┌──────────────┐
                                     │  Pi-hole #2  │  │  Pi-hole #3  │
                                     └──────────────┘  └──────────────┘
```

## What it does

You run two or three Pi-holes so DNS survives a reboot. Blocklists already
keep themselves current — every instance downloads the same adlists on its own
schedule. What drifts is everything you edit *by hand* on the primary: local
DNS records, CNAMEs, groups, allow/deny domains, adlist definitions, client
assignments. holesync mirrors exactly that, and nothing else.

The flagship guarantee: **local DNS records sync with zero DNS downtime.**
Changes go through Pi-hole's live config API, which reloads in place — the
resolver and its `:53` socket are never restarted. Measured at 0 dropped
queries while applying a change under load.

| Data | Default | Notes |
| --- | --- | --- |
| `dns.hosts` (local A/AAAA records) | ✅ on | Config API — in-place reload, zero downtime |
| `dns.cnameRecords` (local CNAMEs) | ✅ on | Same |
| Filtering **groups** | ☑️ opt-in | Synced first; everything else references them |
| **Adlists** (list definitions) | ☑️ opt-in | See the gravity note below |
| Allow/deny **domains** (exact + regex) | ☑️ opt-in | Apply instantly, no rebuild needed |
| **Clients** (per-client group assignments) | ☑️ opt-in | IP/MAC/hostname/subnet |
| Extra **config keys** (`config_keys =`) | ☑️ opt-in | e.g. `dns.upstreams`, `dhcp.hosts` — same zero-downtime PATCH |
| Resolved blocklist (gravity) domains | ❌ never | Each Pi-hole refreshes its own adlists already |

Groups, adlists, domains, and clients are matched by **name, not database id**
— holesync remaps every group reference, so an item on "Kids" lands on the
replica's "Kids" group even when the two databases assigned different ids.

## Why not one of the other sync tools?

Honest answer: the popular tools (nebula-sync, orbital-sync) work by copying a
full Teleporter backup from the primary onto each replica. That's simple and
complete — and importing it **restarts FTL on the replica**, which drops DNS
for a moment, every sync, whether anything changed or not. They also want a
Docker host to live on.

holesync makes the opposite trade: granular API writes, diff-gated so a
steady-state run **writes nothing at all**, no restarts ever, and no runtime
beyond a Python interpreter. The cost: it deliberately syncs *less* (no
Teleporter-style everything-copy — see [DESIGN.md](DESIGN.md) for what's out of
scope and why). If you want a byte-identical clone and don't mind the blip,
use those tools. If you want your replicas quietly converging with zero
interruptions, that's this.

## Quickstart

Requirements: Python 3.9+ (stdlib only), Pi-hole **v6** everywhere, an API
password per Pi-hole.

```bash
git clone <this-repo> && cd holesync
sudo install -m 0755 holesync.py /usr/local/bin/holesync
sudo mkdir -p /etc/holesync /var/lib/holesync/backups
sudo install -m 0600 holesync.conf.example /etc/holesync/holesync.conf
sudoedit /etc/holesync/holesync.conf     # set urls + passwords
```

Minimal config:

```ini
[source]
url = http://10.0.0.10
password = app-password-here

[replica:pihole-02]
url = http://10.0.0.11
password = app-password-here
```

Then work up the confidence ladder:

```bash
holesync --check      # read-only: what differs? (exit 10 if anything)
holesync --dry-run    # what *would* it write?
holesync              # do it
```

Every option is documented inline in
[`holesync.conf.example`](holesync.conf.example).

> **2FA?** A Pi-hole with two-factor auth won't accept its admin password over
> the API. Create an **application password** (Settings → Web interface / API →
> App password) and use that — it's the intended automation credential. Use
> `password_file = /path/to/secret` to keep it out of the config file.

## Usage

```bash
holesync --check          # read-only drift report; exit 10 on drift
holesync --dry-run        # show planned writes, write nothing
holesync                  # sync every replica to the source
holesync -r pihole-02     # just this replica (repeatable)
holesync -v               # per-record debug logging
holesync --force          # override the safety guards (bulk deletes etc.)
```

Exit codes are monitoring-friendly:

| Code | Meaning |
| --- | --- |
| 0 | success — synced, or nothing to do |
| 1 | runtime error |
| 2 | config error |
| 3 | a safety guard refused to write |
| 4 | a write failed verification (rollback attempted) |
| 5 | another holesync run holds the lock |
| 10 | `--check` found drift |

`--check` never reports "in sync" when a replica couldn't be reached — an
unreachable replica is a failure, not a pass.

## Run it on a schedule

```cron
# /etc/cron.d/holesync — every 30 minutes
*/30 * * * * root /usr/local/bin/holesync -c /etc/holesync/holesync.conf >/dev/null 2>&1
```

Or the systemd units in [`systemd/`](systemd/):

```bash
sudo cp systemd/holesync.* /etc/systemd/system/
sudo systemctl enable --now holesync.timer
```

Run it as often as you like. A steady-state run authenticates, reads,
concludes nothing changed, and leaves — well under a second of the good kind
of nothing.

## The safety model

This is the part that matters. Every write path answers four questions first:

1. **Is the source data sane?** Every record is validated (IPs parse,
   hostnames are hostnames, CNAMEs are well-formed). A minimum-record floor
   (`min_hosts`) catches a source that suddenly reports next to nothing.
2. **Is the change plausible?** A **shrink guard** refuses any write that
   would delete more than `max_shrink_pct` of what a replica has (small edits
   exempt via `shrink_min`); a **change cap** (`max_changes`) refuses
   pathological diffs. A genuine bulk change goes through with `--force`.
3. **Is the replica healthy enough to take it?** Before touching the gravity
   database, holesync checks the replica's own diagnostics (won't write into a
   Pi-hole already reporting database trouble) and its responsiveness (defers
   heavy writes when the replica is busy — `load_probe_max`). It also warns
   when source and replica run different FTL versions.
4. **Did the write actually land?** The replica's prior state is **backed up
   to disk** first (rotated, `backup_keep`), every write is **verified by
   read-back**, and a failed verification is **rolled back automatically**.

Writes that do happen are batched (one `:batchDelete`, grouped array-adds) so
a big sync costs a handful of list reloads on the replica, not one per item —
which matters on weak hardware (a Pi-hole in a container on NAS storage can be
wedged by careless bulk writes; see the hard-won lesson in
[DESIGN.md](DESIGN.md)).

### The one gravity caveat

Allow/deny domains, groups, and clients take effect the moment they're
written. **Adlist** changes only take effect after a *gravity* run rebuilds
the blocked-domain set. By default (`run_gravity = false`) holesync leaves
that to the replica's own scheduled gravity cron; set `run_gravity = true` to
rebuild immediately after adlists change — heavier, so it only fires when they
actually changed.

## Development

```bash
python3 -m unittest discover -s tests -v
```

The suite covers validation, diffing, guards, batching, config parsing, retry
logic, and the full sync flows (including verify-failure → rollback) against
in-memory fakes — no network needed. Design rationale and the
what-we-deliberately-don't-do list live in [DESIGN.md](DESIGN.md).

## License

MIT — see [LICENSE](LICENSE).

# holesync

A small, dependency-free replicator that keeps the **local DNS records** of one
or more secondary Pi-holes (v6) in lockstep with a primary, using the Pi-hole
REST API.

It is built for one job and to do it safely: mirror `dns.hosts` and
`dns.cnameRecords` from a source Pi-hole to its replicas, with **no DNS
downtime** and strong guards against propagating a bad read.

```
┌──────────────┐   read /api/config/dns    ┌──────────────┐
│  Pi-hole #1  │ ────────────────────────► │   holesync   │
│  (source)    │                           │  (cron job)  │
└──────────────┘                           └──────┬───────┘
                                                  │ diff, then PATCH only if changed
                                                  ▼
                                          ┌──────────────┐
                                          │  Pi-hole #2  │
                                          │  (replica)   │
                                          └──────────────┘
```

## Why it exists

Pi-hole's blocklists already keep themselves current — each instance refreshes
the same adlists on its own schedule, so the *blocked* domains don't need
syncing. What does drift is the hand-maintained **local DNS** (LAN hostnames and
CNAMEs) you add on the primary. holesync keeps just that in sync, and nothing
else, which is what makes it small and low-risk.

## Highlights

- **Zero-downtime writes.** Changes go through the live config API, which
  reloads DNS in place — the resolver process and its `:53` socket are never
  restarted. Measured at 0 dropped queries while applying a change under load.
- **Diff-gated.** If a replica already matches the source, holesync writes
  nothing at all. A steady-state run is read-only.
- **Corruption-safe by construction:**
  - validates every source record before sending it;
  - a configurable **minimum-record floor** and **drastic-shrink guard** stop a
    transient source glitch from emptying a healthy replica;
  - the replica's current state is **backed up to disk** before any write;
  - every write is **verified by read-back**, and a failed verification is
    **automatically rolled back**.
- **Safe to run on a timer.** `flock` prevents overlapping runs; sessions are
  always closed; transient HTTP errors retry with backoff.
- **No dependencies.** Python 3 standard library only — runs anywhere, including
  low-power hardware.

## Requirements

- Python 3.9+ (standard library only).
- One source Pi-hole and one or more replicas, all running **Pi-hole v6**
  (the REST API introduced in v6), reachable over HTTP(S).
- An admin API password for each Pi-hole.

## Install

```bash
git clone https://github.com/<you>/holesync.git
sudo install -m 0755 holesync/holesync.py /usr/local/bin/holesync
sudo mkdir -p /etc/holesync /var/lib/holesync/backups
sudo install -m 0600 holesync/holesync.conf.example /etc/holesync/holesync.conf
sudoedit /etc/holesync/holesync.conf   # fill in URLs + passwords
```

## Configure

Copy `holesync.conf.example` to `/etc/holesync/holesync.conf`, `chmod 600` it
(it holds passwords), and edit:

```ini
[source]
url = http://10.0.0.10
password = your-admin-password

[replica:pihole-02]
url = http://10.0.0.11
password = your-admin-password

[sync]
hosts = true
cnames = true

[safety]
min_hosts = 5
max_shrink_pct = 50
backup_dir = /var/lib/holesync/backups
backup_keep = 30

[log]
file = /var/log/holesync.log
level = info
```

Add as many `[replica:<name>]` sections as you have replicas. Passwords can be
kept out of the file with `password_file = /path/to/secret` instead of
`password =`.

## Usage

```bash
holesync --check        # read-only: report drift, exit 10 if any replica differs
holesync --dry-run      # show what would change, write nothing
holesync                # apply: sync every replica to the source
holesync -v             # add debug logging (per-record diff)
holesync --force        # apply even past the drastic-shrink guard (bulk deletes)
```

Exit codes: `0` success (incl. already-in-sync) · `1` runtime error · `2` config
error · `3` a safety guard aborted a replica · `4` a write failed verification
(rollback attempted) · `5` another run holds the lock · `10` `--check` found
drift.

## Run it on a schedule

### cron

```cron
# /etc/cron.d/holesync — sync local DNS records hourly
*/30 * * * * root /usr/local/bin/holesync -c /etc/holesync/holesync.conf >/dev/null 2>&1
```

Because holesync is diff-gated, running it often is cheap — most runs are
read-only and finish in well under a second.

### systemd timer (alternative)

Unit files are in [`systemd/`](systemd/):

```bash
sudo cp systemd/holesync.* /etc/systemd/system/
sudo systemctl enable --now holesync.timer
systemctl list-timers holesync.timer
```

## What it syncs (and what it deliberately doesn't)

| Data | Synced | Why |
| --- | --- | --- |
| `dns.hosts` (local A/AAAA records) | ✅ | Hand-maintained on the primary; the thing that actually drifts |
| `dns.cnameRecords` (local CNAMEs) | ✅ | Same |
| Blocklist (gravity) domains | ❌ | Each Pi-hole already refreshes the same adlists itself |
| Adlist / allow / deny *definitions*, groups, clients | ❌ (by design) | Rarely edited; keeping scope small keeps risk low |

Scope is intentionally narrow. If you maintain adlist/allowlist definitions on
the primary and want those mirrored too, that's a natural future addition built
on the same validate → back up → write → verify pattern.

## How a run works

1. Acquire a lock (skip if another run is active).
2. Authenticate to the source, read `dns.hosts` + `dns.cnameRecords` **once**,
   and validate them.
3. For each replica: authenticate, read its current records.
   - If they already match the source → log and move on (no write).
   - Otherwise: run the shrink guard, back up the replica's current state,
     `PATCH` the new records, read them back to verify, and roll back if the
     verification fails.
4. Close all sessions and release the lock.

## Development

```bash
python3 -m unittest discover -s tests -v
```

The test suite covers the validation, diff, equality, and safety-guard logic,
plus the full per-replica flow (no-op, write, dry-run, shrink-abort, and
verify-failure-with-rollback) against an in-memory fake client — no network
required.

## License

MIT — see [LICENSE](LICENSE).

# holesync — design notes

This document is the north star for keeping holesync small and safe. Read it
before adding anything: the goal is a dependable replicator, not a feature pile.

## Scope

holesync mirrors a primary Pi-hole's **user-maintained configuration** to one or
more replicas over the v6 REST API. It does **not** try to be a backup tool, a
DR/Teleporter mechanism, a monitoring system, or a daemon. One job: keep the
replicas' editable config equal to the source's, safely.

## The Pi-hole v6 API surface, and what each write requires

Everything holesync writes falls into two layers with very different costs:

| Layer | Endpoint | Applies when? | Follow-up | Cost on the replica |
| --- | --- | --- | --- | --- |
| **Config** (`pihole.toml`) | `PATCH /api/config` — `dns.hosts`, `dns.cnameRecords` | immediately, in-place reload | none | **cheap** — no DB, no service restart, zero DNS downtime |
| **Gravity DB** (`gravity.db`) | `/api/groups`, `/api/domains/*`, `/api/clients` add/update/delete | immediately (FTL reloads its lists) | none | **medium** — each write triggers a synchronous list reload |
| **Gravity DB** | `/api/lists` (adlists) add/update/delete | row saved immediately | **`POST /api/action/gravity`** to rebuild blocked domains | medium write + **heavy** rebuild |
| Action | `POST /api/action/gravity` | — | — | **very heavy** — downloads + parses every adlist |

Key facts established by testing against live FTL v6.6:

- **DNS records (config layer) are the safe core.** A `PATCH` reloads in place;
  the resolver and its `:53` socket are never torn down. This is the default and
  is always on.
- **Domains, groups, and clients apply on their own** — no gravity rebuild
  needed. Only **adlist content** needs `gravity`, so `run_gravity` is **off by
  default** and a replica's own scheduled gravity cron picks up adlist changes.
- **Group references are per-database.** Adlists/domains/clients reference groups
  by integer id, and ids differ between Pi-holes. holesync syncs groups first and
  **remaps every group reference by name**.

## Efficiency: batch, don't hammer

Each gravity-DB write triggers a list reload. Doing one write per item means one
reload per item — expensive, and dangerous on slow storage. holesync therefore:

- deletes via the `:batchDelete` endpoints (one call per collection), and
- adds via array-form POSTs, grouping items that share attributes,

so a whole-collection sync costs a handful of reloads instead of N. It is also
**diff-gated**: an already-synced replica is read, not written.

## Integrity: the hard-won lesson

A Pi-hole running in a container on **IO-constrained storage** (e.g. a consumer
NAS) cannot absorb heavy `gravity.db` write+reload load. Under IO pressure the
SQLite database locks, FTL wedges, DNS on that node stops answering, and the DB
can corrupt. This is an **environment limit, not an API bug** — batching reduces
the load but a single bulk reload under contention can still wedge a weak node.

holesync's defenses, in order:

1. **DNS-record sync is independent and always safe** — it never touches
   `gravity.db`, so name resolution is never at risk from a sync.
2. **DB-health pre-flight** — before writing gravity collections, read
   `/api/info/messages`; if the replica already reports a database problem,
   refuse to write (don't amplify a bad state).
3. **Load pre-flight** — time a trivial request; if the replica is slow to
   answer, it is busy, so **defer** the gravity-collection writes to a later run
   rather than pile on. (DNS records still sync.)
4. **Backups before writes**, **read-back convergence** (tolerates slow writes),
   and **auto-rollback** on a failed verification.
5. **Guards**: a minimum-record floor, a drastic-shrink guard (with a small-set
   exemption), and a per-collection change cap. `--force` overrides them.

If a replica's gravity database does get corrupted, the recovery is **not**
holesync's job: restore `gravity.db` from `/etc/pihole/gravity_backups/` and run
`pihole -g`. holesync only protects against *causing* it.

## What we deliberately do NOT do

- No Teleporter import/export — it restarts FTL (DNS downtime) and is all-or-
  nothing; the granular API is gentler and diff-able.
- No direct `gravity.db` manipulation — fragile and version-coupled.
- No daemon / scheduler — that's what `cron`/systemd timers are for.
- No clients-as-network-discovery, metrics, or multi-source merging.

## Adding something? Check it against this list

1. Does it touch DNS resolution safety? If yes, it must be opt-in and guarded.
2. Does it add a write that triggers a reload/gravity? Then it must be batched,
   diff-gated, and behind the load pre-flight.
3. Can a cron/timer already do it? Then holesync shouldn't.
4. Does it remap group references by name? Anything new that references groups
   must.

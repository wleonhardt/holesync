# holesync post-fix review — 2026-07-03 (after v1.3.1 / v1.4.0)

Second pass: adversarial review of the fixes themselves, remaining polish
defects (each reproduced), and an expansion menu weighed against DESIGN.md's
scope rules.

## The fixes hold up

Re-read of every changed region plus live verification earlier in the session:
`--check` exit codes correct against a real down replica and real drift; the
`:batchDelete` cleanup exercised W1 logging end-to-end (and caught the 204
false-positive, fixed); lock, rotation, and config parsing covered by tests.
No regressions found.

## Residual polish defects (P — all reproduced)

- **P1 — `password_file` pointing at a missing/unreadable file → uncaught
  `OSError` traceback**, not the clean "config error … exit 2" every other
  config mistake gets. Wrap the read in `_read_password` → `HolesyncError`.
- **P2 — Unreadable config file gives a misleading error.** `cp.read()`
  silently ignores unreadable files, so a permissions problem surfaces as
  "config missing [source] section". Use `cp.read_file(open(path))` so the
  real `OSError` reaches the user (via a `HolesyncError`).
- **P3 — `[replica:]` (empty name) is accepted.** Backup filenames and logs get
  an empty stem. Reject empty names.
- **P4 — Malformed source-side item → top-level traceback.** `process_replica`
  isolates replica-side garbage (W2), but the same garbage on the *source*
  (e.g. a group item with `id` but no `name` → `KeyError` in `group_maps`)
  escapes `main`'s `except HolesyncError`. Add a top-level `except Exception`
  → `LOG.exception` → exit 1, so the lock/exit-code contract holds for
  unexpected errors too.
- **P5 — `logout()` retries against a dead server.** If a replica dies mid-run,
  the best-effort logout still does 3 attempts with backoff (~3s of pointless
  waiting per replica). Logout should be `max_attempts=1`.
- **P6 — Non-root default lockfile is noisy.** `/run/holesync` isn't writable
  for non-root (or existent on macOS), so every unprivileged run warns and
  falls back. Pick the default by privilege: root → `/run/holesync/…`,
  otherwise `$XDG_RUNTIME_DIR` or the temp dir — and only warn when an
  *explicitly configured* path fails.

## Test gaps (T)

- **T1 — `main()` end-to-end**: temp config + fake client → assert exit codes
  (0/2/3/10) through the real CLI path. Would have caught P1/P2/P4.
- **T2 — `_request` retry logic**: fake `_raw` returning 500/429/conn-err
  sequences → assert attempt counts and backoff decisions.

## Expansion menu (checked against DESIGN.md's four questions)

**E1 — DHCP static leases (`dhcp.hosts`) + opt-in extra config keys.** The
config layer holds more hand-maintained state than dns.hosts: static DHCP
leases, `dns.upstreams`, `dns.revServers`, interface settings. All PATCH the
same zero-downtime endpoint holesync already trusts — no gravity DB, no
reloads, same diff→backup→verify→rollback path. Passes all four DESIGN
questions. Two shapes:
  a. `dhcp_hosts = true` — one well-known list key, validated like dns.hosts
     (lease format), shrink-guarded. The hot-standby use-case.
  b. `config_keys = dns.upstreams, dns.revServers, …` — generic opt-in list
     key sync (diff + patch + verify, no per-key validation beyond read-back).
  Recommend (a) first; (b) behind it if wanted. **Effort: M. Value: high** —
  this is the main thing a failover replica still misses.

**E2 — `--replica NAME` CLI filter.** Sync/check one replica (bring-up,
debugging). No new writes, pure selection. **Effort: S.**

**E3 — FTL version pre-flight.** One `GET /api/info/version` per box, log
both, warn on major mismatch. Debugging aid, read-only. **Effort: XS.**

**E4 — CI workflow.** GitHub Actions: unittest matrix (3.9 → 3.14) +
pyflakes. Repo has no remote yet, but the workflow costs nothing to carry.
**Effort: S.**

**E5 — Docs round-out.** README "why not nebula-sync / orbital-sync"
(they Teleporter-import → FTL restart → DNS blip; holesync's niche is granular
zero-downtime) + a restore-from-backup note (closes W7 properly). **Effort: S.**

## Explicitly rejected (DESIGN.md)

Daemon/watch mode, metrics/webhooks, Teleporter transport, bidirectional or
multi-source sync, parallel replica writes, direct gravity.db access. All fail
question 3 ("can cron already do it?") or the complexity bar.

## Suggested order

1. **v1.4.1** — P1–P6 + T1/T2 (small, all defects reproduced today)
2. **v1.5.0** — E1a (dhcp.hosts), plus E2/E3 if wanted
3. Anytime — E4, E5 (docs/CI, no release needed)

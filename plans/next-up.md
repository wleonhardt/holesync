# next-up

## Queue
- [ ] E4: CI workflow (unittest matrix + pyflakes) — now that origin exists, worth adding
- [ ] blocked: replica pihole-02 FTL v6.6.1 vs source v6.6.2. NOT remotely updatable — replica has no SSH (port 22 refused), API-only container on the NAS. Update via NAS/container tooling. Cosmetic only (sync works across the skew).
- [ ] optional: primary PiHole1 has core/web updates (Core 6.4.2->6.4.3, Web 6.5.1->6.6; FTL 6.6.2 fine). User's call.
- [ ] optional: deployed primary config syncs hosts+cnames only — could enable groups/adlists/domains/clients (tested working). Scope decision for the user.

## Done
- [x] Deployed v1.5.0 to primary PiHole1 (2026-07-06): in-place upgrade from a stale 1.2.0 cron install. Backed up old binary -> /usr/local/bin/holesync.1.2.0.bak, verified --check/--dry-run exit 0 against the live deployed config; existing */30 cron already points at /usr/local/bin/holesync (kept cron, not systemd — it works and avoids lockfile-path coordination). Confirmed cron has been firing (17:00–19:00 runs logged).
- [x] Pushed all local commits (were already in sync with origin) + annotated tag v1.5.0 -> github.com/wleonhardt/holesync.
- [x] README rewrite in the "boring on purpose" voice (decision recorded in decisions/); includes the E5 comparison vs Teleporter-based tools
- [x] dhcp.hosts drift: N/A — no Pi-hole serves DHCP on this network (user, 2026-07-03); config_keys stays unset in live conf
- [x] v1.5.0 — E1 `config_keys` (generic config-layer sync incl. dhcp.hosts; shrink-guarded, verified, rolled back; webserver.* refused), E2 `--replica` filter, E3 FTL version pre-flight. Live-verified: found real dhcp.hosts drift + v6.6/v6.6.1 version skew. [postfix review](review-2026-07-03-postfix.md)
- [x] v1.4.1 — P1–P6 polish + T1 main() end-to-end tests + T2 retry-logic tests
- [x] W6 — DROPPED. Live probe (FTL v6.6) proved FTL does not canonicalize `dns.hosts` on write, so there is no flapping risk to guard against. See [open-questions](open-questions.md).
- [x] v1.4.0 — robustness batch: W1 (log non-2xx writes), W2 (per-replica exception isolation), B5 (per-series backup rotation), W3 (import urllib.parse), W5 (public ssl API), W4 (lockfile: no truncate-before-lock, no unlink race, /run default + RuntimeDirectory) + docs (app passwords, cron/max_changes nits) + 5 tests
- [x] v1.3.1 — fixed B1–B4 (config parser inline-comments/interpolation, run_gravity default off, dotted replica names + unknown-section error, --check surfaces failures) + 10 regression tests — [review-2026-07-03](review-2026-07-03.md)

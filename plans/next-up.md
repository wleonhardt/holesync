# next-up

## Queue
- [ ] E4: CI workflow (unittest matrix + pyflakes) — declined for now
- [ ] E5: README comparison vs nebula-sync/orbital-sync + restore-from-backup note — declined for now
- [ ] user: replica still on FTL v6.6.1 after source went to v6.6.2 — update pihole-02

## Done
- [x] dhcp.hosts drift: N/A — no Pi-hole serves DHCP on this network (user, 2026-07-03); config_keys stays unset in live conf
- [x] v1.5.0 — E1 `config_keys` (generic config-layer sync incl. dhcp.hosts; shrink-guarded, verified, rolled back; webserver.* refused), E2 `--replica` filter, E3 FTL version pre-flight. Live-verified: found real dhcp.hosts drift + v6.6/v6.6.1 version skew. [postfix review](review-2026-07-03-postfix.md)
- [x] v1.4.1 — P1–P6 polish + T1 main() end-to-end tests + T2 retry-logic tests
- [x] W6 — DROPPED. Live probe (FTL v6.6) proved FTL does not canonicalize `dns.hosts` on write, so there is no flapping risk to guard against. See [open-questions](open-questions.md).
- [x] v1.4.0 — robustness batch: W1 (log non-2xx writes), W2 (per-replica exception isolation), B5 (per-series backup rotation), W3 (import urllib.parse), W5 (public ssl API), W4 (lockfile: no truncate-before-lock, no unlink race, /run default + RuntimeDirectory) + docs (app passwords, cron/max_changes nits) + 5 tests
- [x] v1.3.1 — fixed B1–B4 (config parser inline-comments/interpolation, run_gravity default off, dotted replica names + unknown-section error, --check surfaces failures) + 10 regression tests — [review-2026-07-03](review-2026-07-03.md)

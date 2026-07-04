# next-up

## Queue
_(empty — review items closed or intentionally dropped)_

## Done
- [x] W6 — DROPPED. Live probe (FTL v6.6) proved FTL does not canonicalize `dns.hosts` on write, so there is no flapping risk to guard against. See [open-questions](open-questions.md).
- [x] v1.4.0 — robustness batch: W1 (log non-2xx writes), W2 (per-replica exception isolation), B5 (per-series backup rotation), W3 (import urllib.parse), W5 (public ssl API), W4 (lockfile: no truncate-before-lock, no unlink race, /run default + RuntimeDirectory) + docs (app passwords, cron/max_changes nits) + 5 tests
- [x] v1.3.1 — fixed B1–B4 (config parser inline-comments/interpolation, run_gravity default off, dotted replica names + unknown-section error, --check surfaces failures) + 10 regression tests — [review-2026-07-03](review-2026-07-03.md)

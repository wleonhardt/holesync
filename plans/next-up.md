# next-up

## Queue
- [ ] canonical hosts/cname comparison (W6) — queued; blocked on [open question](open-questions.md) (does FTL canonicalize on write?)

## Done
- [x] v1.4.0 — robustness batch: W1 (log non-2xx writes), W2 (per-replica exception isolation), B5 (per-series backup rotation), W3 (import urllib.parse), W5 (public ssl API), W4 (lockfile: no truncate-before-lock, no unlink race, /run default + RuntimeDirectory) + docs (app passwords, cron/max_changes nits) + 5 tests
- [x] v1.3.1 — fixed B1–B4 (config parser inline-comments/interpolation, run_gravity default off, dotted replica names + unknown-section error, --check surfaces failures) + 10 regression tests — [review-2026-07-03](review-2026-07-03.md)

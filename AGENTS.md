# AGENTS.md — holesync

## Instruction priority
1. This file
2. `DESIGN.md` (scope north star — read before adding anything)
3. `plans/` (queue, decisions, open questions)

## Non-negotiable rules
- `python3 -m unittest discover -s tests` must pass before work is done.
- No third-party dependencies — Python 3.9+ stdlib only (core design goal).
- Single-file tool: all logic stays in `holesync.py`.
- Any new gravity-DB write must be batched, diff-gated, and behind the load pre-flight (see DESIGN.md checklist).
- Anything referencing groups must remap by name, not id.
- Check `plans/decisions/` before proposing structural changes.
- Never commit `holesync.conf`, `*.pw`, `backups/` (gitignored — they hold secrets/live data).
- Commit after each meaningful change.

## Before-done checklist
- [ ] Tests pass: `python3 -m unittest discover -s tests -v`
- [ ] New pure logic has unit tests (no network — use fakes like `FakeClient`)
- [ ] `holesync.conf.example` + README updated if options changed
- [ ] Version bump in `__version__` for behavior changes

## Project overview
Lightweight Pi-hole v6 config replicator (source → replicas) over the REST API.
Core: local DNS records (`dns.hosts`, `dns.cnameRecords`) via `PATCH /api/config`.
Optional: gravity collections (groups, adlists, domains, clients) with name-based
group remapping, batched writes, safety guards (shrink guard, change cap,
DB-health + load pre-flights), backup/verify/rollback.

Live test environment: primary reachable via `ssh pihole` (FTL v6.6); replica per
`holesync.conf` (not committed).

## Key commands
- Test: `python3 -m unittest discover -s tests -v`
- Dry run: `python3 holesync.py -c holesync.conf --dry-run -v`
- Drift check: `python3 holesync.py -c holesync.conf --check`

## Workspace structure
- `holesync.py` — the entire tool
- `tests/test_holesync.py` — unit tests (pure logic + fake-client flows)
- `holesync.conf.example` — documented config template
- `systemd/` — service + timer units
- `DESIGN.md` — scope + API cost model + safety rationale
- `plans/` — queue, open questions, decisions

## Context recovery
1. Read `DESIGN.md`, then `plans/next-up.md`.
2. `git log --oneline -10` for recent state.
3. Run tests to confirm baseline.

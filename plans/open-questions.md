# open-questions

## Open

## Resolved
- **Does FTL canonicalize `dns.hosts` on write (IPv6 compression, case)?** — **No.** (2026-07-03, FTL v6.6, live replica probe.) Wrote `fd00:0:0:0:0:0:0:99 PROBE.Holesync.Test`, read back byte-identical (IP not compressed, case preserved). ⇒ W6 (canonical comparison) is unnecessary: no canonicalization means no verify→rollback flapping risk. Dropped.

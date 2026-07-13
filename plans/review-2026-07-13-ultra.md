# holesync ultra-review — 2026-07-13 (v1.3.0 → v1.5.0 change set)

Max-effort multi-agent review: 10 finder angles (+4 retried after a session
limit) + adversarial verification + a gap sweep over the full session diff.
69 raw candidates → 15 verified findings. Many were reproduced by executing the
code or probing the live Pi-hole. All 15 are fixed in commit **bc0505d**.

## Verified findings (fixed)

1. **Lock silent tempdir fallback defeats mutual exclusion.** acquire_lock fell
   back to `$TMPDIR/holesync.lock` when the configured path was unwritable — a
   different file, so a root systemd run and a non-root manual run no longer
   excluded each other. → raise `LockError` (exit 2); never relocate.
2. **systemd RuntimeDirectory removal re-introduced the unlink race.** A
   Type=oneshot unit deletes /run/holesync (incl. a held lock) on exit. →
   `RuntimeDirectoryPreserve=yes`.
3. **config_keys accepted non-leaf paths ('dhcp','dns').** Their dict values
   bypassed the list shrink guard (reproduced: 20 leases wiped) and pushed
   replica-specific keys. → reject subtrees; leaf values only.
4. **Dict config_keys: PATCH-merge vs strict-equality verify = permanent
   rollback loop.** Fixed by (3) + order-insensitive compare.
5. **Parser regressions.** inline_comment_prefixes truncated passwords with
   ' #'/' ;' (reproduced); interpolation=None leaves legacy '%%' literal. →
   drop inline comments (passwords literal), rewrite example with full-line
   comments, document the %% migration.
6. **retries=0 → UnboundLocalError** (reproduced). → clamp to ≥1 + init status.
7. **UnicodeDecodeError escaped load_config/_read_password as a traceback**
   (reproduced). → caught → exit 2.
8. **Unguarded tempdir fallback open + never-unlinked stale foreign /tmp lock**
   crashed other users. Subsumed by (1).
9. **Order-sensitive == on config list values** (PLAUSIBLE; live probe
   inconclusive). → `config_values_equal` compares lists as multisets.
10. **config_keys errors exited 1, not 2.** → `ConfigError`; also
    `config_has_key` distinguishes null from absent.
11. **Boom test fake lacked get_version** so it passed via AttributeError, not
    the KeyError path it claimed (reproduced). → add get_version.
12. **run_gravity=True branch had zero coverage.** → GravityRebuildClient + 2
    tests (fires on change; suppressed on dry-run).
13. **Replica-name collisions** ([replica:x] vs [replica.x]; `-r` dupes) shared
    backup filenames. → reject duplicate names; dedup `-r`.
14. **Exit code 4 classified by `"verify failed" in str(e)`.** → `VerifyError`
    type; the collection path's 'did not converge' inconsistency noted.
15. **Shrink guard implemented 3×.** → shared `drastic_shrink()` (DNS + config;
    the collection delete-count variant is intentionally distinct).

## Below the cap (also addressed where cheap)
gravity_timeout undocumented in example (added); write_timeout example/code
mismatch (aligned to 30); AGENTS.md missing the 'knowledge belongs in plans/'
rule (added); dead class-level `import tempfile` (removed).

## Deferred (acknowledged, not changed)
- Efficiency: full-tree GET /api/config where element-addressed GETs exist
  (confirmed cheaper live); per-run get_version probe. Steady-state cost is
  small; revisit if a fleet grows. Logged here so it isn't re-discovered cold.
- `%%` password migration is documented, not auto-detected (literal passwords
  are the better long-term contract).

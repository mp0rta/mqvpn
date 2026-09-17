<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 mp0rta and mqvpn contributors -->

# Formal verification models

This directory contains TLA+ models of mqvpn state machines, checked with
TLC. The models are written *as-is* against the implementation: they encode
what the code does (including deliberately weak guards), not an idealized
design. Divergence between a model and the code it maps is a bug in one of
the two.

## Models

| Model | Maps | Checks |
|-------|------|--------|
| `MqvpnPathSlot.tla` | Single path-slot lifecycle FSM (`src/path_state_machine.c`) composed with an abstract environment (platform, abstract xquic, API, connection reset) | Slot-reuse safety under delayed callbacks, per-state invariants, cleanup liveness, retry accounting |

## How to run

Requires Java 11+ and `tla2tools.jar`
(<https://github.com/tlaplus/tlaplus/releases>).

```bash
# Syntax/semantic check
java -cp tla2tools.jar tla2sany.SANY formal/MqvpnPathSlot.tla

# Safety (config A)
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC \
  -deadlock -workers auto -config formal/MqvpnPathSlot.cfg formal/MqvpnPathSlot.tla

# Liveness (config B, finite-churn constraints)
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC \
  -deadlock -workers auto -config formal/MqvpnPathSlot_live.cfg formal/MqvpnPathSlot.tla
```

Last verified with TLC 2.19: config A explored 561,780 generated /
96,633 distinct states (depth 29), config B 333,830 generated /
59,099 distinct states — both `Model checking completed. No error has
been found.`

## Property ↔ code map (MqvpnPathSlot)

| Property | Kind | What it verifies | Code it maps |
|----------|------|------------------|--------------|
| `TypeOK` | invariant | Variable domains | — |
| `InvPerState` | invariant | Per-state field constraints, exactly the ones `path_invariant_check()` asserts (deliberately not more: e.g. `xqc_path_id` is unasserted in VALIDATING/ACTIVE because the primary slot keeps id 0, and `recreate_retries` is unasserted in CLOSED_FREE) | `src/path_state_machine.c:140-225` |
| `StaleEventHarmless` | action property | A delayed callback belonging to an earlier slot incarnation can never mutate a later incarnation. Holds because of the composed delivery fences: handle lookup for platform events (`find_path_by_handle`; handles are monotonic, `mqvpn_client.c:2651,2760`), xqc_path_id + `xquic_path_live` lookup for xquic removal (`mqvpn_client.c:2184-2202`), and global freshness of xquic path ids — the allocator returns unused ids only (`xqc_conn_get_available_path_id`, `third_party/xquic/src/transport/xqc_conn.c:5444-5467`) *and* abandoned ids are never recycled (ABANDONED cid-set mark, `xqc_multipath.c:219-223`) | reuse scan `mqvpn_client.c:2632-2643` |
| `FdOwnershipSafe` | action property | Only the FD_CLOSED completion of the current incarnation clears the platform-owned fd | `src/path_state_machine.c:672-689` |
| `FreeQuiescent` | action property | CLOSED_FREE is left only by reuse (`add_path_fd`) | `src/path_state_machine.c:640-652` |
| `ReuseOnlyFromFence` | action property | Reuse happens only from public-CLOSED, detached, xquic-drained slots — note this **includes** CLOSED_DROPPED with a still-open fd; the model proves that is safe, see log #1 discussion | `mqvpn_client.c:2616-2691` |
| `DroppedLeadsToFree` | liveness | A dropped slot converges to CLOSED_FREE (or is legitimately reused first) once its two async completions (xquic removal, platform fd close) are fairly delivered | `src/path_state_machine.c:691-700` |
| `RetryEscapes` | liveness | CREATE_WAIT / DEGRADED always escape: activation eventually succeeds, or the retry cap (`>=`, `src/path_state_machine.c:389-390`) forces CLOSED_RECOVERABLE | `src/path_state_machine.c:380-397,483-515` |

## Known abstractions

- **Clock**: all timers are `armed / nondeterministic fire` booleans; backoff
  values, the 30s stable window, and residence warnings are out of scope.
- **Abstract xquic**: the xquic side is reduced to activation outcome
  (OK / transient / permanent), a validation bit, spontaneous abandon, and a
  delayed removal notification. The xquic path FSM itself is a separate
  model (planned).
- **Retry cap shrunk**: `MaxRetries = 2` instead of the production 6 —
  retry-accounting structure is preserved, exhaustion just happens sooner.
- **Handle = incarnation**: `p->handle` is monotonically allocated per slot
  (re)use, so the model unifies handle values with the incarnation counter.
- **Fresh-id allocator kept monotonic across connection resets**: real path
  ids restart per connection, but removals are flushed at reset (see log #1),
  so a cross-connection id collision has no observable effect.
- **Platform contract is assumed**: weak fairness on the fd-close obligation
  encodes the drop contract (the platform must `close()` a dropped fd and
  report completion). A platform that violates the contract is out of
  verification scope.
- **Validation is polled**: mqvpn learns of xquic-side validation via
  `xqc_conn_get_stats` polling (`mqvpn_client.c:3286-3332`), modeled as an
  arbitrarily delayed action, so "VALIDATION_OK arrives after the path was
  already removed" interleavings are covered.
- **Public-event stream is not modeled per emission**: `path_on_event` fires
  the public callback on every internal state change
  (`mqvpn_client.c:400-403`), so an observer sees CLOSED twice on
  DROPPED→FREE and possibly several CLOSED episodes per incarnation via
  manual reactivation. This is intentional implementation behavior; whether
  duplicate CLOSED notifications are desirable for observers is a UX
  question outside this model's scope.

## Counterexample log

Both entries below were TLC counterexamples against earlier model revisions.
Both were triaged as **model over-approximation** (the implementation cannot
reach them); the model was tightened to match the code, with the code
evidence recorded here. Neither is a code bug.

**#1 — id-0 ABA via activation (model artifact).** The first model revision
let a successful activation assign path id 0 (to explore the primary-slot
special case). TLC then produced: incarnation 1 activates with id 0 → drop
queues the removal notification `(id 0, inc 1)` → slot is reused (inc 2) →
reactivates with id 0 → the stale removal is delivered and, since the lookup
matches on `xquic_path_live && xqc_path_id == id` only, it mutates the new
incarnation (`StaleEventHarmless` violation). Not reachable in the
implementation, for two independent reasons: (a) activation allocates via
`xqc_conn_get_available_path_id` (`third_party/xquic/src/transport/xqc_conn.c:5444-5467`),
which only returns *unused* ids — id 0 is held by the initial path and
abandoned ids are excluded by the ABANDONED cid-set mark
(`xqc_multipath.c:219-223`); (b) across connection resets, teardown destroys
remaining paths without firing `path_removed_notify`
(`xqc_conn_destroy_paths_list` → `xqc_path_destroy`,
`xqc_multipath.c:821-830`; the notify only fires in `xqc_path_closed`,
`:603`), so no removal from an old connection survives a reset. Model fix:
fresh nonzero ids only, and CONN_RESET flushes in-flight removals. The
primary slot's id-0 lifecycle (bound at handshake, not via activation)
remains open for the composed model phase.

**#2 — CONN_RESET mutates a CLOSED_FREE slot (model artifact).** An earlier
`FreeQuiescent` demanded full field quiescence in CLOSED_FREE. TLC found:
a slot reaches CLOSED_FREE carrying a stale `recreate_retries` value (the
free gate does not clear it, and `path_invariant_check` deliberately does
not assert it in CLOSED_FREE), then a connection reset — which dispatches
CONN_RESET to *every* slot (`client_reset_paths_for_reconnect`,
`mqvpn_client.c:790-800`) — zeroes it in place. No state change, no public
event (`prior == state` suppresses emission). This is intentional
implementation behavior, so the property was weakened to what the code
guarantees: CLOSED_FREE is left only by reuse.

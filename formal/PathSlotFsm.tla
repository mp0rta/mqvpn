------------------------------ MODULE PathSlotFsm ------------------------------
\* SPDX-License-Identifier: Apache-2.0
\* Copyright (c) 2026 mp0rta and mqvpn contributors
\*
\* The path-slot lifecycle FSM of src/path_state_machine.c as ONE functional
\* operator, Step(s, ev, ctx). This module is the single source of truth for
\* the transition relation: the environment model (MqvpnPathSlot.tla) and the
\* transition oracle (oracle/PathSlotOracle.tla) both INSTANCE it, and the C
\* implementation is checked against the oracle generated from it
\* (tests/test_path_slot_oracle.c, formal/cbmc/).
\*
\* Handler map (src/path_state_machine.c):
\*   OnActivate          path_on_activate_requested
\*   OnRetryTimer        path_on_retry_timer
\*   OnValidationOk      path_on_validation_ok
\*   OnXquicRemoved      path_on_xquic_removed
\*   OnManualReactivate  path_on_manual_reactivate
\*   OnDropLike          path_on_platform_drop, path_on_remove_api
\*   OnAdd               path_on_add
\*   OnConnReset         path_on_conn_reset
\*   OnTransportReleased path_on_transport_released
\*   OnStableTick        path_fsm_tick_confirm_stable (not dispatched through
\*                       path_on_event)
\*   ApplyFailure        apply_failure_with_retry_check
\*   FreeGate            maybe_transition_dropped_to_free
\*   G15                 g_p15_xqc_app_status_for
\*
\* Besides the next slot, Step returns what the C code is observed to do:
\*   fires      path_fsm_fire_path_event() was called (path_on_event fires
\*              exactly when the lifecycle state changed)
\*   notify     the app_status passed to client_notify_xqc_path_state(),
\*              0 when it was not called
\*   retryUpd   how recreate_after_us was updated:   KEEP | ZERO | ARM
\*   stableUpd  how path_stable_since_us was updated: KEEP | ZERO | NOW
\*   retriesUpd how recreate_retries was updated:    KEEP | ZERO | INC
\* ARM = now + path_recreate_backoff(post retries), NOW = now, INC = pre + 1.
\* The update classes are derived from the operation the handler performs,
\* never by comparing abstract values (retries saturates at MaxRetries, so an
\* increment past the cap is invisible in the slot but still INC). The one
\* normalisation: writing 0 over 0 is KEEP, which is decidable here because
\* retryArmed / stableArmed are exactly "the timer is nonzero" and abstract
\* retries 0 is exactly concrete 0.

EXTENDS Naturals

CONSTANT MaxRetries   \* PATH_RECREATE_MAX_RETRIES

NULL == 0

States == {"Pending", "CreateWait", "Validating", "Active", "Standby",
           "Degraded", "ClosedRecoverable", "ClosedDropped", "ClosedFree"}

Events == {"ACTIVATE", "RETRY", "VALIDATION_OK", "XQUIC_REMOVED",
           "MANUAL_REACTIVATE", "PLATFORM_DROP", "REMOVE_API", "ADD",
           "CONN_RESET", "TRANSPORT_RELEASED", "STABLE_TICK"}

Results == {"OK", "TRANSIENT", "PERMANENT"}

\* path_public_status_from_lifecycle
Projection(st) ==
  CASE st \in {"Pending", "CreateWait", "Validating"} -> "PENDING"
    [] st = "Active"   -> "ACTIVE"
    [] st = "Standby"  -> "STANDBY"
    [] st = "Degraded" -> "DEGRADED"
    [] OTHER           -> "CLOSED"

\* path_invariant_check: exactly the per-state constraints the C code asserts
\* (status == projection holds by construction here). xqc_path_id is not
\* asserted in CreateWait / Validating / Active / Standby (the primary slot
\* keeps id 0), and recreate_retries is asserted nowhere.
Legal(s) ==
  LET attachedOk == s.attached /\ ~s.released IN
  CASE s.state = "Pending" ->
         attachedOk /\ ~s.live /\ s.xqcId = NULL /\ ~s.retryArmed /\ ~s.stableArmed
    [] s.state = "CreateWait" ->
         attachedOk /\ ~s.live /\ s.retryArmed
    [] s.state \in {"Validating", "Active", "Standby"} ->
         attachedOk /\ s.live /\ ~s.retryArmed
    [] s.state = "Degraded" ->
         attachedOk /\ ~s.live /\ s.xqcId = NULL /\ s.retryArmed /\ ~s.stableArmed
    [] s.state = "ClosedRecoverable" ->
         attachedOk /\ ~s.live /\ s.xqcId = NULL /\ ~s.retryArmed /\ ~s.stableArmed
    [] s.state = "ClosedDropped" ->
         ~s.attached /\ ~s.retryArmed /\ ~s.stableArmed
    [] s.state = "ClosedFree" ->
         ~s.attached /\ s.released /\ ~s.live /\ s.xqcId = NULL
         /\ ~s.retryArmed /\ ~s.stableArmed

\* g_p15_xqc_app_status_for: 1 = STANDBY, 2 = AVAILABLE, 3 = FROZEN
G15(from, to) ==
  CASE from = "Active" /\ to = "Standby" -> 1
    [] from = "Standby" /\ to = "Active" -> 2
    [] from \in {"Active", "Standby"} /\ to = "Degraded" -> 3
    [] OTHER -> 0

--------------------------------------------------------------------------------
\* Update-class helpers. A write of 0 is ZERO only over a nonzero value.
RetryZero(s)   == IF s.retryArmed THEN "ZERO" ELSE "KEEP"
StableZero(s)  == IF s.stableArmed THEN "ZERO" ELSE "KEEP"
RetriesZero(s) == IF s.retries # 0 THEN "ZERO" ELSE "KEEP"

\* A handler result before the observed outputs are attached.
R(s2, ru, su, rtu) == [slot |-> s2, retryUpd |-> ru, stableUpd |-> su, retriesUpd |-> rtu]

NoOp(s) == R(s, "KEEP", "KEEP", "KEEP")

\* maybe_transition_dropped_to_free, over the already-updated slot
FreeGate(s) ==
  IF s.state = "ClosedDropped" /\ s.released /\ ~s.live /\ s.xqcId = NULL
  THEN [s EXCEPT !.state = "ClosedFree"]
  ELSE s

\* apply_failure_with_retry_check: increments first, then checks with >=
ApplyFailure(s, target) ==
  LET capped == s.retries + 1 >= MaxRetries
      s2 == [s EXCEPT !.live = FALSE, !.xqcId = NULL, !.stableArmed = FALSE,
                      !.retries = IF s.retries < MaxRetries THEN s.retries + 1
                                                            ELSE s.retries,
                      !.retryArmed = ~capped,
                      !.state = IF capped THEN "ClosedRecoverable" ELSE target]
  IN R(s2, IF capped THEN RetryZero(s) ELSE "ARM", StableZero(s), "INC")

\* The OK branch shared by activation, retry and manual reactivation:
\* xqc_path_id = new id, live, recreate_after_us = 0, -> Validating.
ActivateOk(s, newId) ==
  R([s EXCEPT !.xqcId = newId, !.live = TRUE, !.retryArmed = FALSE,
              !.state = "Validating"],
    RetryZero(s), "KEEP", "KEEP")

\* The PERMANENT branch shared by activation and retry: retries untouched.
PermanentFail(s) ==
  R([s EXCEPT !.live = FALSE, !.xqcId = NULL, !.stableArmed = FALSE,
              !.retryArmed = FALSE, !.state = "ClosedRecoverable"],
    RetryZero(s), StableZero(s), "KEEP")

OnActivate(s, ctx) ==
  IF s.state # "Pending" THEN NoOp(s)
  ELSE CASE ctx.result = "OK"        -> ActivateOk(s, ctx.newId)
         [] ctx.result = "TRANSIENT" -> ApplyFailure(s, "CreateWait")
         [] OTHER                    -> PermanentFail(s)

\* Retry target is the current state (self-loop below the cap).
OnRetryTimer(s, ctx) ==
  IF s.state \notin {"CreateWait", "Degraded"} THEN NoOp(s)
  ELSE CASE ctx.result = "OK"        -> ActivateOk(s, ctx.newId)
         [] ctx.result = "TRANSIENT" -> ApplyFailure(s, s.state)
         [] OTHER                    -> PermanentFail(s)

OnValidationOk(s, ctx) ==
  IF s.state # "Validating" THEN NoOp(s)
  ELSE R([s EXCEPT !.stableArmed = TRUE, !.state = ctx.target],
         "KEEP", "NOW", "KEEP")

OnXquicRemoved(s) ==
  CASE s.state = "Validating" -> ApplyFailure(s, "CreateWait")
    [] s.state \in {"Active", "Standby"} -> ApplyFailure(s, "Degraded")
    [] s.state = "ClosedDropped" ->
         R(FreeGate([s EXCEPT !.live = FALSE, !.xqcId = NULL]),
           "KEEP", "KEEP", "KEEP")
    [] OTHER -> NoOp(s)

\* A failed manual reactivation changes nothing (retries and the armed retry
\* timer are deliberately left alone).
OnManualReactivate(s, ctx) ==
  IF s.state \notin {"ClosedRecoverable", "CreateWait", "Degraded"} THEN NoOp(s)
  ELSE IF ctx.result = "OK" THEN ActivateOk(s, ctx.newId)
  ELSE NoOp(s)

\* PLATFORM_DROP and REMOVE_API: same field effects, different reason code.
\* The xquic fields are left for the lazy cleanup.
OnDropLike(s) ==
  IF s.state \in {"ClosedDropped", "ClosedFree"} THEN NoOp(s)
  ELSE R([s EXCEPT !.attached = FALSE, !.retryArmed = FALSE,
                   !.stableArmed = FALSE, !.state = "ClosedDropped"],
         RetryZero(s), StableZero(s), "KEEP")

OnAdd(s) ==
  IF s.state # "ClosedFree" THEN NoOp(s)
  ELSE R([s EXCEPT !.attached = TRUE, !.released = FALSE, !.state = "Pending"],
         "KEEP", "KEEP", "KEEP")

OnConnReset(s) ==
  LET s2 == [s EXCEPT !.live = FALSE, !.xqcId = NULL, !.retryArmed = FALSE,
                      !.retries = 0, !.stableArmed = FALSE]
  IN R(IF s.attached THEN [s2 EXCEPT !.state = "Pending"] ELSE FreeGate(s2),
       RetryZero(s), StableZero(s), RetriesZero(s))

\* Only a CLOSED_DROPPED slot is affected (the caller refuses every other
\* state before dispatching; the handler ignores them too).
OnTransportReleased(s) ==
  IF s.state # "ClosedDropped" THEN NoOp(s)
  ELSE R(FreeGate([s EXCEPT !.released = TRUE]), "KEEP", "KEEP", "KEEP")

\* ctx.reached is the value of the C predicate (now - since) >= 30 s
\* computed in unsigned 64-bit arithmetic.
OnStableTick(s, ctx) ==
  IF s.state \in {"Active", "Standby"} /\ s.stableArmed /\ s.live /\ ctx.reached
  THEN R([s EXCEPT !.retries = 0], "KEEP", "NOW", RetriesZero(s))
  ELSE NoOp(s)

Handle(s, ev, ctx) ==
  CASE ev = "ACTIVATE"           -> OnActivate(s, ctx)
    [] ev = "RETRY"              -> OnRetryTimer(s, ctx)
    [] ev = "VALIDATION_OK"      -> OnValidationOk(s, ctx)
    [] ev = "XQUIC_REMOVED"      -> OnXquicRemoved(s)
    [] ev = "MANUAL_REACTIVATE"  -> OnManualReactivate(s, ctx)
    [] ev = "PLATFORM_DROP"      -> OnDropLike(s)
    [] ev = "REMOVE_API"         -> OnDropLike(s)
    [] ev = "ADD"                -> OnAdd(s)
    [] ev = "CONN_RESET"         -> OnConnReset(s)
    [] ev = "TRANSPORT_RELEASED" -> OnTransportReleased(s)
    [] ev = "STABLE_TICK"        -> OnStableTick(s, ctx)

Step(s, ev, ctx) ==
  LET h == Handle(s, ev, ctx)
  IN [slot       |-> h.slot,
      fires      |-> ev # "STABLE_TICK" /\ h.slot.state # s.state,
      notify     |-> G15(s.state, h.slot.state),
      retryUpd   |-> h.retryUpd,
      stableUpd  |-> h.stableUpd,
      retriesUpd |-> h.retriesUpd]

================================================================================

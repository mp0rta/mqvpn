------------------------------ MODULE MqvpnPathSlot ------------------------------
\* SPDX-License-Identifier: Apache-2.0
\* Copyright (c) 2026 mp0rta and mqvpn contributors
\*
\* As-is model of a single mqvpn path-slot lifecycle FSM
\* (src/path_state_machine.c, 9 states x 10 events, dispatched via
\* path_on_event) composed with an abstract environment:
\*   - platform (drop, fd close obligation and its delayed completion callback)
\*   - abstract xquic (activation outcome, validation, spontaneous abandon,
\*     delayed path-removed notification)
\*   - API (remove_path, add_path_fd slot reuse, manual reactivate)
\*   - connection reset
\*
\* The model encodes what the code does, including deliberately weak guards
\* (e.g. the slot-reuse predicate does NOT require fd < 0), not an idealized
\* design. Delivery guards (handle lookup, xqc_path_id lookup) are modeled
\* as-is so that stale-callback safety is a checked theorem, not an
\* assumption. See formal/README.md for the property <-> code map.

EXTENDS Naturals, FiniteSets

CONSTANTS
  MaxRetries,       \* PATH_RECREATE_MAX_RETRIES (6 in production, shrunk here)
  MaxIncarnations,  \* bound on slot reuse count (>= 3 to exercise ABA shapes)
  MaxXqcIds,        \* bound on fresh xquic path ids handed out by activation
  ConnResetCap,     \* bound on CONN_RESET occurrences (state-space control)
  AbandonCap        \* bound on spontaneous xquic abandons

NULL == 0

States == {"Pending", "CreateWait", "Validating", "Active", "Standby",
           "Degraded", "ClosedRecoverable", "ClosedDropped", "ClosedFree"}

ClosedStates == {"ClosedRecoverable", "ClosedDropped", "ClosedFree"}

\* path_public_status_from_lifecycle (src/path_state_machine.c:121-137)
Projection(s) ==
  CASE s \in {"Pending", "CreateWait", "Validating"} -> "PENDING"
    [] s = "Active"   -> "ACTIVE"
    [] s = "Standby"  -> "STANDBY"
    [] s = "Degraded" -> "DEGRADED"
    [] OTHER          -> "CLOSED"

EventNames == {"NONE", "ACTIVATE", "RETRY", "VALIDATION_OK", "XQUIC_REMOVED",
               "MANUAL_REACTIVATE", "PLATFORM_DROP", "REMOVE_API", "ADD_FD",
               "CONN_RESET", "FD_CLOSED"}

Results == {"OK", "TRANSIENT", "PERMANENT"}

Incs   == 0..MaxIncarnations
XqcIds == 0..MaxXqcIds

VARIABLES
  \* --- slot fields (path_entry_t abstractions) ---
  state,       \* path_lifecycle_t
  attached,    \* platform_attached
  live,        \* xquic_path_live
  xqcId,       \* xqc_path_id (0 = unassigned / primary special case)
  fdOwner,     \* "platform" iff p->fd >= 0 (platform-owned socket), "none" iff fd < 0
  retries,     \* recreate_retries (saturating at MaxRetries)
  retryArmed,  \* recreate_after_us != 0
  stableArmed, \* path_stable_since_us != 0
  \* --- ghost (verification only; handle == inc, p->handle is monotonic) ---
  inc,         \* current incarnation (0 = slot never used); bumped by add_path_fd
  lastTrigger, \* <<event, incarnation tag>> of the event that drove this step
  \* --- environment ---
  pendingXqcRemoval, \* set of <<id, incTag>>: abandon confirmed in xquic,
                     \* cb_path_removed not yet delivered
  pendingFdClose,    \* set of handles: platform close()d the fd,
                     \* on_platform_fd_closed not yet delivered
  fdObligations,     \* set of handles whose platform-owned fd must still be closed
                     \* (drop-contract obligation created at drop/remove dispatch)
  xqcSideActive,     \* abstract xquic: current path passed validation (poll source)
  nextXqcId,         \* fresh path-id allocator (xquic never reuses abandoned ids)
  resetCount, abandonCount

vars == <<state, attached, live, xqcId, fdOwner, retries, retryArmed,
          stableArmed, inc, lastTrigger, pendingXqcRemoval, pendingFdClose,
          fdObligations, xqcSideActive, nextXqcId, resetCount, abandonCount>>

slotVars == <<state, attached, live, xqcId, fdOwner, retries, retryArmed,
              stableArmed>>

envVars == <<pendingXqcRemoval, pendingFdClose, fdObligations, xqcSideActive,
             nextXqcId, resetCount, abandonCount>>

--------------------------------------------------------------------------------
\* FSM internals (transliteration of src/path_state_machine.c; the table in
\* the design doc is normative; guards mirror the code exactly)

\* apply_failure_with_retry_check (path_state_machine.c:380-397).
\* Increments retries first, then checks with >= (NOT >): with production
\* MaxRetries=6 the 6th consecutive failure lands in CLOSED_RECOVERABLE.
ApplyFailure(target) ==
  /\ live'        = FALSE
  /\ xqcId'       = NULL
  /\ stableArmed' = FALSE
  /\ retries'     = IF retries < MaxRetries THEN retries + 1 ELSE retries
  /\ IF retries + 1 >= MaxRetries
     THEN /\ retryArmed' = FALSE
          /\ state'      = "ClosedRecoverable"
     ELSE /\ retryArmed' = TRUE
          /\ state'      = target
  /\ UNCHANGED <<attached, fdOwner>>

\* maybe_transition_dropped_to_free (path_state_machine.c:691-700), specialized
\* per caller: each caller evaluates the gate after its own field update, so
\* the gate condition below is expressed over the post-update values.

\* path_on_activate_requested (path_state_machine.c:452-481)
OnActivateRequested(result, newId) ==
  IF state = "Pending"
  THEN CASE result = "OK" ->
              /\ xqcId'      = newId
              /\ live'       = TRUE
              /\ retryArmed' = FALSE
              /\ state'      = "Validating"
              /\ UNCHANGED <<attached, fdOwner, retries, stableArmed>>
         [] result = "TRANSIENT" -> ApplyFailure("CreateWait")
         [] OTHER ->  \* PERMANENT: retries untouched
              /\ live'       = FALSE
              /\ xqcId'      = NULL
              /\ retryArmed' = FALSE
              /\ state'      = "ClosedRecoverable"
              /\ UNCHANGED <<attached, fdOwner, retries, stableArmed>>
  ELSE UNCHANGED slotVars  \* WARN no-op

\* path_on_retry_timer (path_state_machine.c:483-515); retry target is the
\* current state (self-loop on TRANSIENT below the retry cap)
OnRetryTimer(result, newId) ==
  IF state \in {"CreateWait", "Degraded"}
  THEN CASE result = "OK" ->
              /\ xqcId'      = newId
              /\ live'       = TRUE
              /\ retryArmed' = FALSE
              /\ state'      = "Validating"
              /\ UNCHANGED <<attached, fdOwner, retries, stableArmed>>
         [] result = "TRANSIENT" -> ApplyFailure(state)
         [] OTHER ->
              /\ live'       = FALSE
              /\ xqcId'      = NULL
              /\ retryArmed' = FALSE
              /\ state'      = "ClosedRecoverable"
              /\ UNCHANGED <<attached, fdOwner, retries, stableArmed>>
  ELSE UNCHANGED slotVars  \* WARN no-op

\* path_on_validation_ok (path_state_machine.c:517-531)
OnValidationOk(target) ==
  IF state = "Validating"
  THEN /\ stableArmed' = TRUE
       /\ state'       = target
       /\ UNCHANGED <<attached, live, xqcId, fdOwner, retries, retryArmed>>
  ELSE UNCHANGED slotVars  \* LOG_D no-op (late async after remove)

\* path_on_xquic_removed (path_state_machine.c:533-560)
OnXquicRemoved ==
  CASE state = "Validating" -> ApplyFailure("CreateWait")
    [] state \in {"Active", "Standby"} -> ApplyFailure("Degraded")
    [] state = "ClosedDropped" ->
         \* lazy cleanup re-evaluation branch + free gate
         /\ live'  = FALSE
         /\ xqcId' = NULL
         /\ state' = IF fdOwner = "none" THEN "ClosedFree" ELSE "ClosedDropped"
         /\ UNCHANGED <<attached, fdOwner, retries, retryArmed, stableArmed>>
    [] OTHER -> UNCHANGED slotVars  \* WARN no-op

\* path_on_manual_reactivate (path_state_machine.c:562-607).
\* On failure: no state change, retries NOT incremented, recreate_after_us
\* deliberately left intact.
OnManualReactivate(result, newId) ==
  IF state \in {"ClosedRecoverable", "CreateWait", "Degraded"}
  THEN IF result = "OK"
       THEN /\ xqcId'      = newId
            /\ live'       = TRUE
            /\ retryArmed' = FALSE
            /\ state'      = "Validating"
            /\ UNCHANGED <<attached, fdOwner, retries, stableArmed>>
       ELSE UNCHANGED slotVars
  ELSE UNCHANGED slotVars  \* WARN no-op (API-gate bug if reached)

\* path_on_platform_drop (path_state_machine.c:609-623) and
\* path_on_remove_api (path_state_machine.c:625-638): same field effects,
\* different reason code. fd / xquic fields left intact (lazy).
OnDropLike ==
  IF state \in {"ClosedDropped", "ClosedFree"}
  THEN UNCHANGED slotVars  \* idempotent
  ELSE /\ attached'    = FALSE
       /\ retryArmed'  = FALSE
       /\ stableArmed' = FALSE
       /\ state'       = "ClosedDropped"
       /\ UNCHANGED <<live, xqcId, fdOwner, retries>>

\* path_on_conn_reset (path_state_machine.c:654-670): unconditional clear,
\* retries reset to 0; attached slots restart in PENDING, detached slots
\* re-evaluate the free gate.
OnConnReset ==
  /\ live'        = FALSE
  /\ xqcId'       = NULL
  /\ retryArmed'  = FALSE
  /\ retries'     = 0
  /\ stableArmed' = FALSE
  /\ state' = IF attached
              THEN "Pending"
              ELSE IF state = "ClosedDropped" /\ fdOwner = "none"
                   THEN "ClosedFree"
                   ELSE state
  /\ UNCHANGED <<attached, fdOwner>>

\* path_on_fd_closed (path_state_machine.c:672-689) + free gate evaluated
\* after fd is cleared
OnFdClosed ==
  IF state = "ClosedDropped"
  THEN /\ fdOwner' = "none"
       /\ state'   = IF live = FALSE /\ xqcId = NULL
                     THEN "ClosedFree" ELSE "ClosedDropped"
       /\ UNCHANGED <<attached, live, xqcId, retries, retryArmed, stableArmed>>
  ELSE UNCHANGED slotVars  \* LOG_D no-op (stale handle never reaches here;
                           \* this branch exists for in-incarnation ordering)

--------------------------------------------------------------------------------
\* Environment actions. Each action that dispatches an FSM event also stamps
\* lastTrigger with <<event, incarnation tag>>; pure environment steps leave
\* lastTrigger unchanged.

\* Fresh-id selection for successful activations: xquic never reuses an
\* abandoned path_id (abandoned_path_ids bitmap, xqc_multipath.c:109-137), so
\* real ids are globally fresh. Id 0 is additionally allowed to model the
\* primary-path special case kept by the design doc (path_invariant_check
\* does not assert xqc_path_id in VALIDATING/ACTIVE precisely because the
\* primary slot keeps id 0).
OkIdChoices ==
  {NULL} \cup (IF nextXqcId <= MaxXqcIds THEN {nextXqcId} ELSE {})

BumpAllocator(newId) ==
  nextXqcId' = IF newId = nextXqcId THEN nextXqcId + 1 ELSE nextXqcId

\* activate_pending_paths -> ACTIVATE_REQUESTED (mqvpn_client.c, via
\* cb_ready_to_create_path / activate_via_xquic_classify)
EnvActivate ==
  /\ inc >= 1
  /\ state = "Pending"
  /\ \E result \in Results :
       IF result = "OK"
       THEN \E newId \in OkIdChoices :
              /\ OnActivateRequested("OK", newId)
              /\ BumpAllocator(newId)
              /\ xqcSideActive' = FALSE  \* new path starts unvalidated
              /\ lastTrigger' = <<"ACTIVATE", inc>>
              /\ UNCHANGED <<inc, pendingXqcRemoval, pendingFdClose,
                             fdObligations, resetCount, abandonCount>>
       ELSE /\ OnActivateRequested(result, NULL)
            /\ lastTrigger' = <<"ACTIVATE", inc>>
            /\ UNCHANGED <<inc, pendingXqcRemoval, pendingFdClose,
                           fdObligations, xqcSideActive, nextXqcId,
                           resetCount, abandonCount>>

\* tick_drive_retry_timer -> RETRY_TIMER (mqvpn_client.c:3249-3273); the
\* timer can only fire while armed, in the states the dispatcher checks
EnvRetryFire ==
  /\ inc >= 1
  /\ retryArmed
  /\ state \in {"CreateWait", "Degraded"}
  /\ \E result \in Results :
       IF result = "OK"
       THEN \E newId \in OkIdChoices :
              /\ OnRetryTimer("OK", newId)
              /\ BumpAllocator(newId)
              /\ xqcSideActive' = FALSE
              /\ lastTrigger' = <<"RETRY", inc>>
              /\ UNCHANGED <<inc, pendingXqcRemoval, pendingFdClose,
                             fdObligations, resetCount, abandonCount>>
       ELSE /\ OnRetryTimer(result, NULL)
            /\ lastTrigger' = <<"RETRY", inc>>
            /\ UNCHANGED <<inc, pendingXqcRemoval, pendingFdClose,
                           fdObligations, xqcSideActive, nextXqcId,
                           resetCount, abandonCount>>

\* mqvpn_client_manual_reactivate path -> MANUAL_REACTIVATE
ApiManualReactivate ==
  /\ inc >= 1
  /\ state \in {"ClosedRecoverable", "CreateWait", "Degraded"}
  /\ \E result \in Results :
       IF result = "OK"
       THEN \E newId \in OkIdChoices :
              /\ OnManualReactivate("OK", newId)
              /\ BumpAllocator(newId)
              /\ xqcSideActive' = FALSE
              /\ lastTrigger' = <<"MANUAL_REACTIVATE", inc>>
              /\ UNCHANGED <<inc, pendingXqcRemoval, pendingFdClose,
                             fdObligations, resetCount, abandonCount>>
       ELSE /\ OnManualReactivate(result, NULL)
            /\ lastTrigger' = <<"MANUAL_REACTIVATE", inc>>
            /\ UNCHANGED <<inc, pendingXqcRemoval, pendingFdClose,
                           fdObligations, xqcSideActive, nextXqcId,
                           resetCount, abandonCount>>

\* Abstract xquic internal step: PATH_RESPONSE received, path becomes ACTIVE
\* on the xquic side. Blocked once an abandon for the current path is in
\* flight (a CLOSING path cannot validate).
EnvXqcValidate ==
  /\ inc >= 1
  /\ live
  /\ ~xqcSideActive
  /\ <<xqcId, inc>> \notin pendingXqcRemoval
  /\ xqcSideActive' = TRUE
  /\ UNCHANGED <<state, attached, live, xqcId, fdOwner, retries, retryArmed,
                 stableArmed, inc, lastTrigger, pendingXqcRemoval,
                 pendingFdClose, fdObligations, nextXqcId, resetCount,
                 abandonCount>>

\* tick_check_all_validations -> VALIDATION_OK (mqvpn_client.c:3286-3332).
\* Dispatch-side guard state==VALIDATING (:3297,:3309) is modeled in addition
\* to the FSM handler guard, matching the implementation's double check.
\* Poll delay is the nondeterministic scheduling of this action.
EnvValidationPoll ==
  /\ inc >= 1
  /\ state = "Validating"
  /\ xqcSideActive
  /\ \E target \in {"Active", "Standby"} :
       /\ OnValidationOk(target)
       /\ lastTrigger' = <<"VALIDATION_OK", inc>>
  /\ UNCHANGED <<inc, pendingXqcRemoval, pendingFdClose, fdObligations,
                 xqcSideActive, nextXqcId, resetCount, abandonCount>>

\* xquic-originated abandon without any local close_path: validation timeout
\* (xqc_path_validation_on_retx -> xqc_path_request_abandon,
\* third_party/xquic/src/transport/xqc_multipath.c:460-484), idle timeout,
\* etc. mqvpn learns about it only via the later cb_path_removed delivery.
EnvXqcSpontaneousAbandon ==
  /\ inc >= 1
  /\ live
  /\ abandonCount < AbandonCap
  /\ <<xqcId, inc>> \notin pendingXqcRemoval
  /\ pendingXqcRemoval' = pendingXqcRemoval \cup {<<xqcId, inc>>}
  /\ xqcSideActive' = FALSE
  /\ abandonCount' = abandonCount + 1
  /\ UNCHANGED <<state, attached, live, xqcId, fdOwner, retries, retryArmed,
                 stableArmed, inc, lastTrigger, pendingFdClose, fdObligations,
                 nextXqcId, resetCount>>

\* cb_path_removed -> find_path_by_xqc_id -> XQUIC_REMOVED
\* (mqvpn_client.c:2184-2202). Delivery guard is as-is: the slot is found
\* only if it is xquic-live with a matching id; otherwise the notification
\* is silently discarded (:2191-2195). The incarnation tag rides along as
\* ghost data only - the real lookup cannot see it.
DeliverRemoval ==
  \E e \in pendingXqcRemoval :
    /\ pendingXqcRemoval' = pendingXqcRemoval \ {e}
    /\ IF live /\ xqcId = e[1]
       THEN /\ OnXquicRemoved
            /\ lastTrigger' = <<"XQUIC_REMOVED", e[2]>>
       ELSE /\ UNCHANGED slotVars
            /\ UNCHANGED lastTrigger
    /\ UNCHANGED <<inc, pendingFdClose, fdObligations, xqcSideActive,
                   nextXqcId, resetCount, abandonCount>>

\* mqvpn_client_on_platform_path_dropped (mqvpn_client.c:2726-2753):
\* issues a non-blocking close_path while the slot is still xquic-live
\* (queues the eventual removal notification), then dispatches PLATFORM_DROP.
\* The platform now owes a close() of the slot's fd (drop contract).
ApiDrop ==
  /\ inc >= 1
  /\ state /= "ClosedFree"
  /\ pendingXqcRemoval' = IF live
                          THEN pendingXqcRemoval \cup {<<xqcId, inc>>}
                          ELSE pendingXqcRemoval
  /\ fdObligations' = IF fdOwner = "platform"
                      THEN fdObligations \cup {inc}
                      ELSE fdObligations
  /\ OnDropLike
  /\ xqcSideActive' = FALSE
  /\ lastTrigger' = <<"PLATFORM_DROP", inc>>
  /\ UNCHANGED <<inc, pendingFdClose, nextXqcId, resetCount, abandonCount>>

\* mqvpn_client_remove_path (mqvpn_client.c:2694-2724): same close-then-
\* dispatch shape with an orderly reason code; returns early on CLOSED_FREE.
ApiRemove ==
  /\ inc >= 1
  /\ state /= "ClosedFree"
  /\ pendingXqcRemoval' = IF live
                          THEN pendingXqcRemoval \cup {<<xqcId, inc>>}
                          ELSE pendingXqcRemoval
  /\ fdObligations' = IF fdOwner = "platform"
                      THEN fdObligations \cup {inc}
                      ELSE fdObligations
  /\ OnDropLike
  /\ xqcSideActive' = FALSE
  /\ lastTrigger' = <<"REMOVE_API", inc>>
  /\ UNCHANGED <<inc, pendingFdClose, nextXqcId, resetCount, abandonCount>>

\* Platform closes an owed fd (drop contract step 3). Two-phase with
\* delivery: close() happens here, the FD_CLOSED callback lands later.
PlatformFdClose ==
  \E h \in fdObligations :
    /\ fdObligations' = fdObligations \ {h}
    /\ pendingFdClose' = pendingFdClose \cup {h}
    /\ UNCHANGED <<state, attached, live, xqcId, fdOwner, retries, retryArmed,
                   stableArmed, inc, lastTrigger, pendingXqcRemoval,
                   xqcSideActive, nextXqcId, resetCount, abandonCount>>

\* mqvpn_client_on_platform_fd_closed (mqvpn_client.c:2755-2766):
\* find_path_by_handle succeeds only for the current handle - handles are
\* monotonic and never reused, so a stale handle is rejected with
\* MQVPN_ERR_INVALID_ARG and nothing is dispatched.
DeliverFdClose ==
  \E h \in pendingFdClose :
    /\ pendingFdClose' = pendingFdClose \ {h}
    /\ IF h = inc
       THEN /\ OnFdClosed
            /\ lastTrigger' = <<"FD_CLOSED", h>>
       ELSE /\ UNCHANGED slotVars
            /\ UNCHANGED lastTrigger
    /\ UNCHANGED <<inc, pendingXqcRemoval, fdObligations, xqcSideActive,
                   nextXqcId, resetCount, abandonCount>>

\* mqvpn_client_add_path_fd_with_outcome (mqvpn_client.c:2616-2691), one
\* atomic API call: weak reuse scan (public status CLOSED, not attached, not
\* xquic-live - fd < 0 deliberately NOT required), path_entry_init (forced
\* reset), fresh handle assignment (p->handle = c->next_path_handle++,
\* :2651), new platform-owned fd, then the ADD_FD event lands in PENDING.
\* Also covers the fresh-append case (initial inc = 0 slot).
ApiAddFd ==
  /\ inc < MaxIncarnations
  /\ Projection(state) = "CLOSED"
  /\ ~attached
  /\ ~live
  /\ state'       = "Pending"
  /\ attached'    = TRUE
  /\ live'        = FALSE
  /\ xqcId'       = NULL
  /\ fdOwner'     = "platform"
  /\ retries'     = 0
  /\ retryArmed'  = FALSE
  /\ stableArmed' = FALSE
  /\ inc'         = inc + 1
  /\ lastTrigger' = <<"ADD_FD", inc + 1>>
  /\ UNCHANGED <<pendingXqcRemoval, pendingFdClose, fdObligations,
                 xqcSideActive, nextXqcId, resetCount, abandonCount>>

\* client_reset_paths_for_reconnect -> client_reset_path_runtime ->
\* CONN_RESET (mqvpn_client.c:774-800). Pending notifications are retained
\* (conservative; see design doc 4.3).
EnvConnReset ==
  /\ inc >= 1
  /\ resetCount < ConnResetCap
  /\ OnConnReset
  /\ xqcSideActive' = FALSE
  /\ resetCount' = resetCount + 1
  /\ lastTrigger' = <<"CONN_RESET", inc>>
  /\ UNCHANGED <<inc, pendingXqcRemoval, pendingFdClose, fdObligations,
                 nextXqcId, abandonCount>>

--------------------------------------------------------------------------------

Init ==
  /\ state = "ClosedFree"
  /\ attached = FALSE
  /\ live = FALSE
  /\ xqcId = NULL
  /\ fdOwner = "none"
  /\ retries = 0
  /\ retryArmed = FALSE
  /\ stableArmed = FALSE
  /\ inc = 0
  /\ lastTrigger = <<"NONE", 0>>
  /\ pendingXqcRemoval = {}
  /\ pendingFdClose = {}
  /\ fdObligations = {}
  /\ xqcSideActive = FALSE
  /\ nextXqcId = 1
  /\ resetCount = 0
  /\ abandonCount = 0

Next ==
  \/ EnvActivate
  \/ EnvRetryFire
  \/ ApiManualReactivate
  \/ EnvXqcValidate
  \/ EnvValidationPoll
  \/ EnvXqcSpontaneousAbandon
  \/ DeliverRemoval
  \/ ApiDrop
  \/ ApiRemove
  \/ PlatformFdClose
  \/ DeliverFdClose
  \/ ApiAddFd
  \/ EnvConnReset

Spec == Init /\ [][Next]_vars

\* Fairness (liveness config only). Delivery actions are non-parameterized
\* existentials, so WF on each guarantees the pending sets drain. WF on
\* PlatformFdClose encodes the platform drop-contract obligation (the
\* platform MUST close() a dropped fd and report it); a platform that
\* violates the contract is out of verification scope.
Fairness ==
  /\ WF_vars(DeliverRemoval)
  /\ WF_vars(DeliverFdClose)
  /\ WF_vars(PlatformFdClose)
  /\ WF_vars(EnvRetryFire)
  /\ WF_vars(EnvValidationPoll)
  /\ WF_vars(EnvXqcValidate)

LiveSpec == Init /\ [][Next]_vars /\ Fairness

--------------------------------------------------------------------------------
\* Properties

TypeOK ==
  /\ state \in States
  /\ attached \in BOOLEAN
  /\ live \in BOOLEAN
  /\ xqcId \in XqcIds
  /\ fdOwner \in {"none", "platform"}
  /\ retries \in 0..MaxRetries
  /\ retryArmed \in BOOLEAN
  /\ stableArmed \in BOOLEAN
  /\ inc \in Incs
  /\ lastTrigger \in EventNames \X Incs
  /\ pendingXqcRemoval \subseteq (XqcIds \X (1..MaxIncarnations))
  /\ pendingFdClose \subseteq (1..MaxIncarnations)
  /\ fdObligations \subseteq (1..MaxIncarnations)
  /\ xqcSideActive \in BOOLEAN
  /\ nextXqcId \in 1..(MaxXqcIds + 1)
  /\ resetCount \in 0..ConnResetCap
  /\ abandonCount \in 0..AbandonCap

\* path_invariant_check (src/path_state_machine.c:140-225), transliterated:
\* only the constraints the code actually asserts (e.g. xqc_path_id is
\* deliberately NOT asserted in CREATE_WAIT / VALIDATING / ACTIVE / STANDBY
\* because the primary slot keeps id 0).
InvPerState ==
  /\ (state = "Pending") =>
       (attached /\ ~live /\ fdOwner = "platform" /\ xqcId = NULL
        /\ ~retryArmed /\ ~stableArmed)
  /\ (state = "CreateWait") =>
       (attached /\ ~live /\ fdOwner = "platform" /\ retryArmed)
  /\ (state \in {"Validating", "Active", "Standby"}) =>
       (attached /\ live /\ fdOwner = "platform" /\ ~retryArmed)
  /\ (state = "Degraded") =>
       (attached /\ ~live /\ fdOwner = "platform" /\ xqcId = NULL
        /\ retryArmed /\ ~stableArmed)
  /\ (state = "ClosedRecoverable") =>
       (attached /\ ~live /\ fdOwner = "platform" /\ xqcId = NULL
        /\ ~retryArmed /\ ~stableArmed)
  /\ (state = "ClosedDropped") =>
       (~attached /\ ~retryArmed /\ ~stableArmed)
  /\ (state = "ClosedFree") =>
       (~attached /\ ~live /\ fdOwner = "none" /\ xqcId = NULL
        /\ ~retryArmed /\ ~stableArmed)

\* P1a: a stale event never mutates a newer incarnation's slot. Every
\* slot-mutating step must have been triggered by an event tagged with the
\* (possibly just-bumped) current incarnation.
StaleEventHarmless ==
  [][ slotVars' /= slotVars => lastTrigger'[2] = inc' ]_vars

\* P1b: fd ownership - only the FD_CLOSED completion of the current
\* incarnation may clear the platform-owned fd. (Slot reuse hands the slot a
\* NEW platform fd, so fdOwner stays "platform" across ApiAddFd.)
FdOwnershipSafe ==
  [][ (fdOwner = "platform" /\ fdOwner' = "none")
        => lastTrigger' = <<"FD_CLOSED", inc>> ]_vars

\* P4 (design doc rev4): ClosedFree is terminal for the incarnation - the
\* only slot-mutating step out of it is reuse, which bumps inc.
FreeQuiescent ==
  [][ (state = "ClosedFree" /\ slotVars' /= slotVars)
        => inc' = inc + 1 ]_vars

\* Design doc rev5: reuse is possible from exactly the weak-fence states
\* (public CLOSED, detached, xquic-drained). ClosedDropped with an
\* still-open fd IS legitimately reusable - the platform closes the old fd
\* later and the stale FD_CLOSED is rejected by the handle lookup.
ReuseOnlyFromFence ==
  [][ inc' > inc =>
        (state \in {"ClosedDropped", "ClosedFree"} /\ ~attached /\ ~live) ]_vars

\* P3: a dropped slot eventually reaches ClosedFree, or is legitimately
\* reused first (reuse does not require passing through ClosedFree - see
\* ReuseOnlyFromFence).
DroppedLeadsToFree ==
  \A i \in 1..MaxIncarnations :
    (state = "ClosedDropped" /\ inc = i) ~> (state = "ClosedFree" \/ inc > i)

\* P5: retry states always escape - either an activation eventually succeeds
\* (Validating) or the retry cap forces ClosedRecoverable; external drops /
\* resets exit to ClosedDropped / Pending.
RetryEscapes ==
  (state \in {"CreateWait", "Degraded"}) ~>
    (state \in {"Validating", "ClosedRecoverable", "ClosedDropped", "Pending"})

================================================================================

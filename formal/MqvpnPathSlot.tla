------------------------------ MODULE MqvpnPathSlot ------------------------------
\* SPDX-License-Identifier: Apache-2.0
\* Copyright (c) 2026 mp0rta and mqvpn contributors
\*
\* One mqvpn client path slot (the FSM of PathSlotFsm.tla) inside an abstract
\* environment: the connection lifecycle (connect, handshake, close,
\* reconnect), an abstract xquic (activation outcome, path validation,
\* PATH_ABANDON and the path-removed notification, idle timeouts), the
\* platform (drop / remove, the transport release it owes, late and
\* duplicated release calls) and the whole-object destroy. Every environment
\* action is an as-is transcription of its caller in src/mqvpn_client.c,
\* guards included; see formal/README.md for the map and the assumptions.
\*
\* With a single slot, the slot is always the primary path.

EXTENDS Naturals, FiniteSets

CONSTANTS
  MaxRetries,       \* PATH_RECREATE_MAX_RETRIES (6 in production, shrunk here)
  MaxIncarnations,  \* bound on add_path (slot reuse) calls
  MaxXqcIds,        \* bound on fresh xquic path ids handed out by activation
  ConnCloseCap,     \* bound on arbitrary connection closes (EnvConnClose)
  AbandonCap,       \* bound on spontaneous xquic abandons
  DupReleaseCap     \* bound on duplicated / late release calls

Fsm == INSTANCE PathSlotFsm

NULL == 0

Incs   == 0..MaxIncarnations
XqcIds == 0..MaxXqcIds

\* mqvpn_state_t, reduced to what the slot's environment distinguishes:
\* Idle (never connected), Connecting (xquic connection exists, handshake /
\* tunnel setup in progress), TunnelReady (address assigned), Established
\* (the platform activated the TUN; tick_path_recovery runs), Reconnecting
\* (connection destroyed, retry timer armed), Closed (terminal).
ConnStates == {"Idle", "Connecting", "TunnelReady", "Established",
               "Reconnecting", "Closed"}
ConnUp == {"Connecting", "TunnelReady", "Established"}

TriggerNames == {"NONE", "ACTIVATE", "RETRY", "VALIDATION_OK", "XQUIC_REMOVED",
                 "MANUAL_REACTIVATE", "PLATFORM_DROP", "REMOVE_API", "ADD",
                 "CONN_RESET", "TRANSPORT_RELEASED", "STABLE_TICK", "BOOTSTRAP"}

\* path_entry_init: what add_path starts from before dispatching ADD.
FreshSlot == [state |-> "ClosedFree", attached |-> FALSE, live |-> FALSE,
              released |-> TRUE, xqcId |-> NULL, retries |-> 0,
              retryArmed |-> FALSE, stableArmed |-> FALSE]

VARIABLES
  slot,          \* the abstract path_entry_t (PathSlotFsm record)
  opsSet,        \* p->ops.send != NULL: a transport is installed
  \* --- ghost ---
  inc,           \* current incarnation = the slot's handle (0: never added)
  lastTrigger,   \* <<event, incarnation>> of the event that drove this step
  releaseCount,  \* ops.release() calls per incarnation
  destroyed,     \* mqvpn_client_destroy() ran
  \* --- connection ---
  conn,          \* see ConnStates
  mpReady,       \* c->multipath_ready
  mp,            \* a negotiated multipath connection (fixed at Init)
  mpCredit,      \* the peer grants path-id credit (fixed at Init; meaningful
                 \* only with mp)
  closeCount,    \* EnvConnClose occurrences (bounded)
  \* --- abstract xquic ---
  xqcSideActive, \* the slot's xquic path is ACTIVE on the xquic side
  pendingXqcRemoval, \* <<id, incarnation>>: path closed in xquic, removal
                     \* notification not yet delivered
  nextXqcId,     \* fresh-id allocator (xquic never reuses a path id)
  abandonCount,  \* spontaneous abandons (bounded)
  \* --- platform ---
  releaseObligations, \* handles whose release the platform still owes
  pendingRelease,     \* release calls made, not yet processed
  dupCount            \* duplicated / late release calls (bounded)

vars == <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed, conn,
          mpReady, mp, mpCredit, closeCount, xqcSideActive, pendingXqcRemoval,
          nextXqcId, abandonCount, releaseObligations, pendingRelease,
          dupCount>>

--------------------------------------------------------------------------------
\* Helpers

NoCtx == [result |-> "-", newId |-> NULL, target |-> "-", reached |-> FALSE]

\* Dispatch ev on the slot, stamping the trigger with the current incarnation.
Fire(ev, ctx) ==
  /\ slot' = Fsm!Step(slot, ev, ctx).slot
  /\ lastTrigger' = <<ev, inc>>

\* The primary bootstrap in cli_start_connection (mqvpn_client.c:2896-2902):
\* direct writes, no public event. xquic creates the initial path ACTIVE
\* (xqc_path_init, xqc_multipath.c:351-353).
Bootstrapped(s) == [s EXCEPT !.xqcId = 0, !.live = TRUE, !.state = "Validating"]

\* A dropped slot whose xquic path is still alive and not being removed.
Orphan ==
  /\ slot.state = "ClosedDropped"
  /\ slot.live
  /\ <<slot.xqcId, inc>> \notin pendingXqcRemoval
  /\ conn \in ConnUp

\* Fresh id for a successful activation: xqc_conn_get_available_path_id
\* returns the next unused id, never 0 (held by the initial path) and never
\* an abandoned one (xqc_conn.c:5519-5542; the abandoned-id bitmap,
\* xqc_multipath.c:109-137).
OkIdChoices == IF nextXqcId <= MaxXqcIds THEN {nextXqcId} ELSE {}

\* The three activation entry points share this shape: a nondeterministic
\* outcome, a fresh id on success, and a new path that starts unvalidated.
Activation(ev) ==
  \E result \in Fsm!Results :
    IF result = "OK"
    THEN \E id \in OkIdChoices :
           /\ Fire(ev, [NoCtx EXCEPT !.result = "OK", !.newId = id])
           /\ nextXqcId' = nextXqcId + 1
           /\ xqcSideActive' = FALSE
    ELSE /\ Fire(ev, [NoCtx EXCEPT !.result = result])
         /\ UNCHANGED <<nextXqcId, xqcSideActive>>

\* The connection is gone: xquic destroys its paths without notifying
\* (xqc_conn_destroy_paths_list), so in-flight removals are dropped.
\* cb_h3_conn_close (mqvpn_client.c:1426-1452) leaves the slot as it is and
\* goes to RECONNECTING, or to CLOSED when reconnect is off or shutting down.
ConnDown ==
  /\ conn' \in {"Reconnecting", "Closed"}
  /\ pendingXqcRemoval' = {}
  /\ xqcSideActive' = FALSE

--------------------------------------------------------------------------------
\* Connection

\* mqvpn_client_connect from IDLE: no slot reset; cli_start_connection
\* refuses a primary that is not attached (mqvpn_client.c:2811-2818), which
\* leaves the client IDLE (a stutter, omitted).
ApiConnect ==
  /\ conn = "Idle"
  /\ slot.attached
  /\ slot' = Bootstrapped(slot)
  /\ lastTrigger' = <<"BOOTSTRAP", inc>>
  /\ conn' = "Connecting"
  /\ xqcSideActive' = TRUE
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, mpReady, mp, mpCredit, closeCount,
                 pendingXqcRemoval, nextXqcId, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

\* cb_ready_to_create_path: xquic signals multipath readiness after the
\* handshake, only on a multipath connection and only once a path id is
\* available, i.e. the peer granted path-id credit (xqc_engine.c:785-800,
\* xqc_conn_get_available_path_id, xqc_conn.c:5519-5542). It can precede the
\* tunnel address and ESTABLISHED. Runs where the peer never grants credit
\* (mpCredit = FALSE) are explored too: the client then never becomes ready.
EnvMpReady ==
  /\ conn \in ConnUp
  /\ mp
  /\ mpCredit
  /\ ~mpReady
  /\ mpReady' = TRUE
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed, conn,
                 mp, mpCredit, closeCount, xqcSideActive, pendingXqcRemoval, nextXqcId,
                 abandonCount, releaseObligations, pendingRelease, dupCount>>

\* Address assigned -> TUNNEL_READY; the primary, if still VALIDATING and
\* attached, is validated by the handshake (mqvpn_client.c:2143-2152).
EnvTunnelReady ==
  /\ conn = "Connecting"
  /\ conn' = "TunnelReady"
  /\ IF slot.state = "Validating" /\ slot.attached
     THEN Fire("VALIDATION_OK", [NoCtx EXCEPT !.target = "Active"])
     ELSE UNCHANGED <<slot, lastTrigger>>
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, mpReady, mp, mpCredit, closeCount,
                 xqcSideActive, pendingXqcRemoval, nextXqcId, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

\* mqvpn_client_set_tun_active: TUNNEL_READY -> ESTABLISHED.
EnvEstablish ==
  /\ conn = "TunnelReady"
  /\ conn' = "Established"
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed,
                 mpReady, mp, mpCredit, closeCount, xqcSideActive, pendingXqcRemoval,
                 nextXqcId, abandonCount, releaseObligations, pendingRelease,
                 dupCount>>

\* Any connection close: peer, network, handshake failure, disconnect().
EnvConnClose ==
  /\ conn \in ConnUp
  /\ closeCount < ConnCloseCap
  /\ closeCount' = closeCount + 1
  /\ ConnDown
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed,
                 mpReady, mp, mpCredit, nextXqcId, abandonCount, releaseObligations,
                 pendingRelease, dupCount>>

\* tick_reconnect, or mqvpn_client_connect from RECONNECTING (both reset the
\* slots, then start: mqvpn_client.c:3202-3233, 4108-4140). The reset runs
\* whether or not the start succeeds; the start fails when the primary is not
\* attached, and may fail anyway (xqc_h3_connect), which re-arms the timer.
EnvReconnect ==
  /\ conn = "Reconnecting"
  /\ LET reset == Fsm!Step(slot, "CONN_RESET", NoCtx).slot IN
       \/ /\ reset.attached
          /\ slot' = Bootstrapped(reset)
          /\ conn' = "Connecting"
          /\ xqcSideActive' = TRUE
       \/ /\ slot' = reset
          /\ UNCHANGED <<conn, xqcSideActive>>
  /\ lastTrigger' = <<"CONN_RESET", inc>>
  /\ mpReady' = FALSE
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, mp, mpCredit, closeCount,
                 pendingXqcRemoval, nextXqcId, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

\* disconnect() while RECONNECTING cancels the retry.
ApiDisconnectWhileReconnecting ==
  /\ conn = "Reconnecting"
  /\ conn' = "Closed"
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed,
                 mpReady, mp, mpCredit, closeCount, xqcSideActive, pendingXqcRemoval,
                 nextXqcId, abandonCount, releaseObligations, pendingRelease,
                 dupCount>>

--------------------------------------------------------------------------------
\* Activation, retry, validation, stability (the client's own triggers)

\* activate_pending_paths: from cb_ready_to_create_path and from add_path
\* once multipath is ready on a live connection. PENDING only.
EnvActivate ==
  /\ conn \in ConnUp
  /\ mpReady
  /\ slot.state = "Pending"
  /\ Activation("ACTIVATE")
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, conn, mpReady, mp, mpCredit,
                 closeCount, pendingXqcRemoval, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

\* tick_path_recovery runs only when multipath is ready and ESTABLISHED
\* (mqvpn_client.c:4091-4103).
Ticking == conn = "Established" /\ mpReady

\* tick_drive_retry_timer (mqvpn_client.c:4002-4020)
EnvRetryFire ==
  /\ Ticking
  /\ slot.state \in {"CreateWait", "Degraded"}
  /\ slot.retryArmed
  /\ Activation("RETRY")
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, conn, mpReady, mp, mpCredit,
                 closeCount, pendingXqcRemoval, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

\* tick_check_all_validations polls xquic (mqvpn_client.c:4039-4083); the
\* target is ACTIVE or STANDBY per the scheduler.
EnvValidationPoll ==
  /\ Ticking
  /\ slot.state = "Validating"
  /\ xqcSideActive
  /\ \E t \in {"Active", "Standby"} :
       Fire("VALIDATION_OK", [NoCtx EXCEPT !.target = t])
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, conn, mpReady, mp, mpCredit,
                 closeCount, xqcSideActive, pendingXqcRemoval, nextXqcId,
                 abandonCount, releaseObligations, pendingRelease, dupCount>>

\* path_fsm_tick_confirm_stable once the 30 s window has elapsed.
EnvStableConfirm ==
  /\ Ticking
  /\ slot.state \in {"Active", "Standby"}
  /\ slot.stableArmed
  /\ slot.live
  /\ Fire("STABLE_TICK", [NoCtx EXCEPT !.reached = TRUE])
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, conn, mpReady, mp, mpCredit,
                 closeCount, xqcSideActive, pendingXqcRemoval, nextXqcId,
                 abandonCount, releaseObligations, pendingRelease, dupCount>>

\* mqvpn_client_reactivate_path: ESTABLISHED + multipath ready, then
\* reactivate_slot_eligible (mqvpn_client.c:3549-3594).
ApiManualReactivate ==
  /\ inc >= 1
  /\ Ticking
  /\ ~slot.live
  /\ slot.attached
  /\ slot.state \in {"ClosedRecoverable", "CreateWait", "Degraded"}
  /\ Activation("MANUAL_REACTIVATE")
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, conn, mpReady, mp, mpCredit,
                 closeCount, pendingXqcRemoval, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

--------------------------------------------------------------------------------
\* Abstract xquic

\* The slot's path passes validation on the xquic side (PATH_RESPONSE).
EnvXqcValidate ==
  /\ conn \in ConnUp
  /\ slot.live
  /\ ~xqcSideActive
  /\ <<slot.xqcId, inc>> \notin pendingXqcRemoval
  /\ xqcSideActive' = TRUE
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed, conn,
                 mpReady, mp, mpCredit, closeCount, pendingXqcRemoval, nextXqcId,
                 abandonCount, releaseObligations, pendingRelease, dupCount>>

\* xquic abandons a path on its own when its validation times out
\* (xqc_path_validation_on_retx, xqc_multipath.c:460-484): multipath only,
\* and only a path that is not xquic-ACTIVE. With one slot an xquic-ACTIVE
\* path is the only active path, which the path idle timeout never closes
\* (xqc_timer.c:137-161); an orphan's idle routes are EnvPathIdleReap and
\* EnvConnIdleTimeout. Bounded and not fair.
EnvXqcSpontaneousAbandon ==
  /\ conn \in ConnUp
  /\ mp
  /\ ~xqcSideActive
  /\ slot.live
  /\ abandonCount < AbandonCap
  /\ <<slot.xqcId, inc>> \notin pendingXqcRemoval
  /\ pendingXqcRemoval' = pendingXqcRemoval \cup {<<slot.xqcId, inc>>}
  /\ xqcSideActive' = FALSE
  /\ abandonCount' = abandonCount + 1
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed, conn,
                 mpReady, mp, mpCredit, closeCount, nextXqcId, releaseObligations,
                 pendingRelease, dupCount>>

\* cb_path_removed -> find_path_by_xqc_id -> XQUIC_REMOVED (mqvpn_client.c:
\* 561-569, 2704-2721). The lookup matches a live slot with the same id only;
\* the incarnation rides along as ghost data the real lookup cannot see.
DeliverRemoval ==
  /\ conn \in ConnUp
  /\ \E e \in pendingXqcRemoval :
       /\ pendingXqcRemoval' = pendingXqcRemoval \ {e}
       /\ IF slot.live /\ slot.xqcId = e[1]
          THEN /\ slot' = Fsm!Step(slot, "XQUIC_REMOVED", NoCtx).slot
               /\ lastTrigger' = <<"XQUIC_REMOVED", e[2]>>
          ELSE UNCHANGED <<slot, lastTrigger>>
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, conn, mpReady, mp, mpCredit,
                 closeCount, xqcSideActive, nextXqcId, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

\* The two recovery routes of an orphan (a dropped slot whose PATH_ABANDON
\* failed or was never sent), exactly as xqc_timer_path_idle_timeout
\* (xqc_timer.c:137-161) splits them. With one slot, an xquic-ACTIVE path
\* is the only active path, which the path idle timeout never closes, and
\* neither does it without multipath: then the connection idles out.
EnvPathIdleReap ==
  /\ Orphan
  /\ mp
  /\ ~xqcSideActive
  /\ pendingXqcRemoval' = pendingXqcRemoval \cup {<<slot.xqcId, inc>>}
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed, conn,
                 mpReady, mp, mpCredit, closeCount, xqcSideActive, nextXqcId,
                 abandonCount, releaseObligations, pendingRelease, dupCount>>

\* Not counted against ConnCloseCap: an orphan exists at most once per
\* incarnation (after the close, a reset clears live or the client stays
\* Closed), so this is bounded by MaxIncarnations.
EnvConnIdleTimeout ==
  /\ Orphan
  /\ ~mp \/ xqcSideActive
  /\ ConnDown
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed,
                 mpReady, mp, mpCredit, closeCount, nextXqcId, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

--------------------------------------------------------------------------------
\* Platform and API

\* mqvpn_client_add_path (mqvpn_client.c:3362-3441): reuses only a
\* CLOSED_FREE slot (MQVPN_MAX_PATHS aside, a single-slot model has nowhere
\* to append), path_entry_init, a fresh handle, the transport installed,
\* then ADD. Covers the never-used slot too (inc = 0, FreshSlot).
ApiAdd ==
  /\ inc < MaxIncarnations
  /\ slot.state = "ClosedFree"
  /\ slot' = Fsm!Step(FreshSlot, "ADD", NoCtx).slot
  /\ opsSet' = TRUE
  /\ inc' = inc + 1
  /\ lastTrigger' = <<"ADD", inc + 1>>
  /\ UNCHANGED <<releaseCount, destroyed, conn, mpReady, mp, mpCredit, closeCount,
                 xqcSideActive, pendingXqcRemoval, nextXqcId, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

\* mqvpn_client_on_platform_path_dropped / mqvpn_client_remove_path
\* (mqvpn_client.c:3456-3508): a live path is abandoned first, only when a
\* connection exists; xqc_conn_close_path may fail (multipath off, only
\* active path, closing: xqc_multipath.c:751-787) and the caller ignores
\* that. A failed abandon leaves the xquic path as it was. Then the event;
\* the platform now owes the release of an installed transport.
DropLike(ev) ==
  /\ inc >= 1
  /\ slot.state # "ClosedFree"
  /\ \E abandonOk \in (IF slot.live /\ conn \in ConnUp /\ mp
                       THEN BOOLEAN ELSE {FALSE}) :
       IF abandonOk
       THEN /\ pendingXqcRemoval' = pendingXqcRemoval \cup {<<slot.xqcId, inc>>}
            /\ xqcSideActive' = FALSE
       ELSE UNCHANGED <<pendingXqcRemoval, xqcSideActive>>
  /\ Fire(ev, NoCtx)
  /\ releaseObligations' = IF opsSet /\ ~slot.released
                           THEN releaseObligations \cup {inc}
                           ELSE releaseObligations
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, conn, mpReady, mp, mpCredit,
                 closeCount, nextXqcId, abandonCount, pendingRelease, dupCount>>

ApiDrop   == DropLike("PLATFORM_DROP")
ApiRemove == DropLike("REMOVE_API")

\* The platform stops I/O, closes its socket and reports the release.
PlatformRelease ==
  \E h \in releaseObligations :
    /\ releaseObligations' = releaseObligations \ {h}
    /\ pendingRelease' = pendingRelease \cup {h}
    /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed,
                   conn, mpReady, mp, mpCredit, closeCount, xqcSideActive,
                   pendingXqcRemoval, nextXqcId, abandonCount, dupCount>>

\* A release call for any handle ever issued, again or out of turn.
PlatformDupRelease ==
  /\ dupCount < DupReleaseCap
  /\ \E h \in 1..inc :
       /\ pendingRelease' = pendingRelease \cup {h}
       /\ dupCount' = dupCount + 1
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed, conn,
                 mpReady, mp, mpCredit, closeCount, xqcSideActive, pendingXqcRemoval,
                 nextXqcId, abandonCount, releaseObligations>>

\* mqvpn_client_on_platform_path_released (mqvpn_client.c:3512-3535), its
\* guards in order: unknown/recycled handle, CLOSED_FREE (late duplicate),
\* not CLOSED_DROPPED (refused), already released or no transport; only
\* then client_finalize_transport (ops.release) and TRANSPORT_RELEASED.
DeliverRelease ==
  \E h \in pendingRelease :
    /\ pendingRelease' = pendingRelease \ {h}
    /\ IF /\ h = inc
          /\ slot.state = "ClosedDropped"
          /\ ~slot.released
          /\ opsSet
       THEN /\ opsSet' = FALSE
            /\ releaseCount' = [releaseCount EXCEPT ![h] = @ + 1]
            /\ Fire("TRANSPORT_RELEASED", NoCtx)
       ELSE UNCHANGED <<opsSet, releaseCount, slot, lastTrigger>>
    /\ UNCHANGED <<inc, destroyed, conn, mpReady, mp, mpCredit, closeCount,
                   xqcSideActive, pendingXqcRemoval, nextXqcId, abandonCount,
                   releaseObligations, dupCount>>

\* mqvpn_client_destroy (mqvpn_client.c:3123-3170) finalises every slot that
\* still owes a release, without setting the flag. client_finalize_transport
\* calls ops.release only through the ops it snapshots, which an earlier
\* finalise already cleared (mqvpn_client.c:964-981): hence opsSet. Nothing
\* happens after destroy.
EnvDestroy ==
  /\ destroyed' = TRUE
  /\ IF ~slot.released /\ opsSet
     THEN /\ releaseCount' = [releaseCount EXCEPT ![inc] = @ + 1]
          /\ opsSet' = FALSE
     ELSE UNCHANGED <<releaseCount, opsSet>>
  /\ UNCHANGED <<slot, inc, lastTrigger, conn, mpReady, mp, mpCredit, closeCount,
                 xqcSideActive, pendingXqcRemoval, nextXqcId, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

--------------------------------------------------------------------------------

Init ==
  /\ slot = FreshSlot
  /\ opsSet = FALSE
  /\ inc = 0
  /\ lastTrigger = <<"NONE", 0>>
  /\ releaseCount = [i \in 1..MaxIncarnations |-> 0]
  /\ destroyed = FALSE
  /\ conn = "Idle"
  /\ mpReady = FALSE
  /\ mp \in BOOLEAN
  /\ mpCredit \in BOOLEAN
  /\ closeCount = 0
  /\ xqcSideActive = FALSE
  /\ pendingXqcRemoval = {}
  /\ nextXqcId = 1
  /\ abandonCount = 0
  /\ releaseObligations = {}
  /\ pendingRelease = {}
  /\ dupCount = 0

Next ==
  /\ ~destroyed
  /\ \/ ApiConnect \/ EnvMpReady \/ EnvTunnelReady \/ EnvEstablish
     \/ EnvConnClose \/ EnvReconnect \/ ApiDisconnectWhileReconnecting
     \/ EnvActivate \/ EnvRetryFire \/ EnvValidationPoll \/ EnvStableConfirm
     \/ ApiManualReactivate
     \/ EnvXqcValidate \/ EnvXqcSpontaneousAbandon \/ DeliverRemoval
     \/ EnvPathIdleReap \/ EnvConnIdleTimeout
     \/ ApiAdd \/ ApiDrop \/ ApiRemove
     \/ PlatformRelease \/ PlatformDupRelease \/ DeliverRelease
     \/ EnvDestroy

Spec == Init /\ [][Next]_vars

\* Fairness = the environment assumptions (formal/README.md). Destroy,
\* arbitrary closes, disconnects, spontaneous abandons, API calls, duplicated
\* releases, xquic-side validation and the validation poll may or may not
\* happen: neither liveness property needs a path to validate.
Fairness ==
  /\ WF_vars(~destroyed /\ DeliverRemoval)
  /\ WF_vars(~destroyed /\ PlatformRelease)
  /\ WF_vars(~destroyed /\ DeliverRelease)
  /\ WF_vars(~destroyed /\ EnvMpReady)
  /\ WF_vars(~destroyed /\ EnvTunnelReady)
  /\ WF_vars(~destroyed /\ EnvEstablish)
  /\ WF_vars(~destroyed /\ EnvReconnect)
  /\ WF_vars(~destroyed /\ EnvRetryFire)
  /\ WF_vars(~destroyed /\ EnvPathIdleReap)
  /\ WF_vars(~destroyed /\ EnvConnIdleTimeout)

LiveSpec == Spec /\ Fairness

--------------------------------------------------------------------------------
\* Properties

TypeOK ==
  /\ slot \in [state : Fsm!States, attached : BOOLEAN, live : BOOLEAN,
               released : BOOLEAN, xqcId : XqcIds, retries : 0..MaxRetries,
               retryArmed : BOOLEAN, stableArmed : BOOLEAN]
  /\ opsSet \in BOOLEAN
  /\ inc \in Incs
  /\ lastTrigger \in TriggerNames \X Incs
  /\ releaseCount \in [1..MaxIncarnations -> 0..2]
  /\ destroyed \in BOOLEAN
  /\ conn \in ConnStates
  /\ mpReady \in BOOLEAN
  /\ mp \in BOOLEAN
  /\ mpCredit \in BOOLEAN
  /\ closeCount \in 0..ConnCloseCap
  /\ xqcSideActive \in BOOLEAN
  /\ pendingXqcRemoval \subseteq (XqcIds \X (1..MaxIncarnations))
  /\ nextXqcId \in 1..(MaxXqcIds + 1)
  /\ abandonCount \in 0..AbandonCap
  /\ releaseObligations \subseteq 1..MaxIncarnations
  /\ pendingRelease \subseteq 1..MaxIncarnations
  /\ dupCount \in 0..DupReleaseCap

\* path_invariant_check holds in every reachable state.
InvPerState == Fsm!Legal(slot)

\* The C concretization rule: a transport is installed exactly while a
\* release is owed.
OpsConsistent == ~destroyed => (opsSet <=> ~slot.released)

\* ops.release() runs at most once per incarnation ...
ReleaseAtMostOnce == \A i \in 1..MaxIncarnations : releaseCount[i] <= 1

\* ... every earlier incarnation was released before its slot was reused ...
EarlierIncarnationsReleased == \A i \in 1..MaxIncarnations : i < inc => releaseCount[i] = 1

\* ... the release flag of the current incarnation is the ghost count ...
ReleasedMeansFinalized ==
  ~destroyed => (slot.released <=> (inc = 0 \/ releaseCount[inc] = 1))

\* ... and after destroy nothing is leaked.
NoLeakAtDestroy == destroyed => \A i \in 1..MaxIncarnations : i <= inc => releaseCount[i] = 1

\* No removal notification outlives its incarnation. CLOSED_FREE, the only
\* state a slot is reused from, needs live = 0, which only a delivered
\* removal or a reset clears, and a reset follows a connection close, which
\* discards the in-flight removals. So the id-keyed lookup of cb_path_removed
\* can never meet a removal of an earlier incarnation.
RemovalsBelongToCurrentIncarnation == \A e \in pendingXqcRemoval : e[2] = inc

\* A delayed event of an earlier incarnation never changes the slot: every
\* step that changes it was triggered by the current incarnation.
StaleEventHarmless ==
  [][ slot' # slot => lastTrigger'[2] = inc' ]_vars

\* CLOSED_FREE is left only by reuse.
FreeQuiescent ==
  [][ (slot.state = "ClosedFree" /\ slot'.state # "ClosedFree") => inc' = inc + 1 ]_vars

\* A dropped slot reaches CLOSED_FREE, unless the client is destroyed or its
\* connection is closed for good (then a live xquic binding may stay behind
\* until destroy: README finding).
DroppedLeadsToFree ==
  \A i \in 1..MaxIncarnations :
    (slot.state = "ClosedDropped" /\ inc = i)
      ~> (slot.state = "ClosedFree" \/ destroyed \/ conn = "Closed")

\* The retry states always escape.
RetryEscapes ==
  (slot.state \in {"CreateWait", "Degraded"})
    ~> (slot.state \in {"Validating", "ClosedRecoverable", "ClosedDropped", "Pending"}
        \/ destroyed \/ conn = "Closed")

================================================================================

----------------------------- MODULE MqvpnPathSlot -----------------------------
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
\* guards included, with two deliberate exceptions, both
\* over-approximations: PATH_ABANDON may succeed on the slot's xquic-ACTIVE
\* path (see DropLike), and the validation poll chooses its target per poll,
\* where the code fixes it per connection (see EnvValidationPoll). Work the
\* code does synchronously inside one call is split into separate steps
\* here: the activate_pending_paths of add_path (ApiAdd, then EnvActivate)
\* and of cb_ready_to_create_path (EnvMpReady, then EnvActivate), and the
\* tick's validation, retry and stable passes (EnvValidationPoll,
\* EnvRetryFire, EnvStableConfirm). See formal/README.md for the map and
\* the assumptions.
\*
\* With a single slot, the slot is always the primary path.

EXTENDS Naturals

CONSTANTS
  MaxRetries,       \* PATH_RECREATE_MAX_RETRIES (6 in production, shrunk here)
  MaxIncarnations,  \* bound on add_path (slot reuse) calls
  MaxXqcIds,        \* the xquic path ids TypeOK allows (0..MaxXqcIds). It
                    \* limits no action: a run that uses them all up fails
                    \* TypeOK, which only the safety configuration checks
  ConnCloseCap,     \* bound on arbitrary connection closes (EnvConnClose)
  AbandonCap,       \* bound on spontaneous xquic abandons
  DupReleaseCap     \* bound on duplicated / late release calls

Fsm == INSTANCE PathSlotFsm

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

\* What stamps lastTrigger: an FSM event, the primary bootstrap's direct
\* writes, or NONE before either has happened.
TriggerNames == Fsm!Events \cup {"BOOTSTRAP", "NONE"}

\* path_entry_init: what add_path starts from before dispatching ADD.
FreshSlot == [state |-> "ClosedFree", attached |-> FALSE, live |-> FALSE,
              released |-> TRUE, xqcId |-> Fsm!NULL, retries |-> 0,
              retryArmed |-> FALSE, stableArmed |-> FALSE]

VARIABLES
  slot,          \* the abstract path_entry_t (PathSlotFsm record)
  opsSet,        \* p->ops.send != NULL: a transport is installed
  \* --- ghost ---
  inc,           \* current incarnation = the slot's handle (0: never added)
  lastTrigger,   \* <<event, incarnation>> of the event that drove this step
  releaseCount,  \* transport finalisations (client_finalize_transport) per
                 \* incarnation; the ops.release a finalisation calls is
                 \* optional
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
  nextXqcId,     \* the next fresh xquic path id. xquic reuses no id within
                 \* a connection; this counter does not restart for a new
                 \* one either, which loses nothing: ConnDown drops every
                 \* pending removal
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

NoCtx == [result |-> "-", newId |-> Fsm!NULL, target |-> "-",
          reached |-> FALSE]

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

\* The three activation entry points share this shape: a nondeterministic
\* outcome, a fresh id on success, and a new path that starts unvalidated.
\* xqc_conn_get_available_path_id returns the next unused id, never 0 (held
\* by the initial path) and never an abandoned one (xqc_conn.c:5519-5542;
\* the abandoned-id bitmap, xqc_multipath.c:109-137). MaxXqcIds limits
\* nothing here: a run that uses up the ids fails TypeOK, loudly but only in
\* the safety run (the live configuration does not check TypeOK).
Activation(ev) ==
  \E result \in Fsm!Results :
    IF result = "OK"
    THEN /\ Fire(ev, [NoCtx EXCEPT !.result = "OK", !.newId = nextXqcId])
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
\* (mqvpn_client.c:2811-2818) refuses a primary that is not attached, which
\* leaves the client IDLE (a stutter, omitted).
ApiConnect ==
  /\ ~destroyed
  /\ conn = "Idle"
  /\ slot.attached
  /\ slot' = Bootstrapped(slot)
  /\ lastTrigger' = <<"BOOTSTRAP", inc>>
  /\ conn' = "Connecting"
  /\ xqcSideActive' = TRUE
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, mpReady, mp, mpCredit,
                 closeCount, pendingXqcRemoval, nextXqcId, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

\* cb_ready_to_create_path: xquic signals multipath readiness after the
\* handshake, only on a multipath connection and only once a path id is
\* available, i.e. the peer granted path-id credit (xqc_engine.c:785-800,
\* xqc_conn_get_available_path_id, xqc_conn.c:5519-5542). It can precede the
\* tunnel address and ESTABLISHED. Runs where the peer never grants credit
\* (mpCredit = FALSE) are explored too: the client then never becomes ready.
EnvMpReady ==
  /\ ~destroyed
  /\ conn \in ConnUp
  /\ mp
  /\ mpCredit
  /\ ~mpReady
  /\ mpReady' = TRUE
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed, conn,
                 mp, mpCredit, closeCount, xqcSideActive, pendingXqcRemoval,
                 nextXqcId, abandonCount, releaseObligations, pendingRelease,
                 dupCount>>

\* Address assigned -> TUNNEL_READY; the primary, if still VALIDATING and
\* attached, is validated by the handshake (cli_connect_ip_on_body,
\* mqvpn_client.c:2143-2152).
EnvTunnelReady ==
  /\ ~destroyed
  /\ conn = "Connecting"
  /\ conn' = "TunnelReady"
  /\ IF slot.state = "Validating" /\ slot.attached
     THEN Fire("VALIDATION_OK", [NoCtx EXCEPT !.target = "Active"])
     ELSE UNCHANGED <<slot, lastTrigger>>
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, mpReady, mp, mpCredit,
                 closeCount, xqcSideActive, pendingXqcRemoval, nextXqcId,
                 abandonCount, releaseObligations, pendingRelease, dupCount>>

\* mqvpn_client_set_tun_active: TUNNEL_READY -> ESTABLISHED.
EnvEstablish ==
  /\ ~destroyed
  /\ conn = "TunnelReady"
  /\ conn' = "Established"
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed,
                 mpReady, mp, mpCredit, closeCount, xqcSideActive,
                 pendingXqcRemoval, nextXqcId, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

\* Any connection close: peer, network, handshake failure, disconnect().
EnvConnClose ==
  /\ ~destroyed
  /\ conn \in ConnUp
  /\ closeCount < ConnCloseCap
  /\ closeCount' = closeCount + 1
  /\ ConnDown
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed,
                 mpReady, mp, mpCredit, nextXqcId, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

\* tick_reconnect (mqvpn_client.c:4108-4140), or mqvpn_client_connect from
\* RECONNECTING (mqvpn_client.c:3202-3262): both reset the slots, then start.
\* The reset runs whether or not the start succeeds; the start fails when
\* the primary is not attached, and may fail anyway (xqc_h3_connect), which
\* re-arms the timer.
EnvReconnect ==
  /\ ~destroyed
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
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, mp, mpCredit,
                 closeCount, pendingXqcRemoval, nextXqcId, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

\* disconnect() while RECONNECTING cancels the retry.
ApiDisconnectWhileReconnecting ==
  /\ ~destroyed
  /\ conn = "Reconnecting"
  /\ conn' = "Closed"
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed,
                 mpReady, mp, mpCredit, closeCount, xqcSideActive,
                 pendingXqcRemoval, nextXqcId, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

--------------------------------------------------------------------------------
\* Activation, retry, validation, stability (the client's own triggers)

\* activate_pending_paths: from cb_ready_to_create_path and from add_path
\* once multipath is ready on a live connection. PENDING only.
EnvActivate ==
  /\ ~destroyed
  /\ conn \in ConnUp
  /\ mpReady
  /\ slot.state = "Pending"
  /\ Activation("ACTIVATE")
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, conn, mpReady, mp,
                 mpCredit, closeCount, pendingXqcRemoval, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

\* tick_path_recovery (mqvpn_client.c:4091-4103) runs only when multipath is
\* ready and ESTABLISHED.
Ticking == conn = "Established" /\ mpReady

\* tick_drive_retry_timer (mqvpn_client.c:4002-4020)
EnvRetryFire ==
  /\ ~destroyed
  /\ Ticking
  /\ slot.state \in {"CreateWait", "Degraded"}
  /\ slot.retryArmed
  /\ Activation("RETRY")
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, conn, mpReady, mp,
                 mpCredit, closeCount, pendingXqcRemoval, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

\* tick_check_all_validations (mqvpn_client.c:4039-4083) polls xquic and
\* validates a slot whose path is xquic-ACTIVE. The code takes the target
\* from the scheduler, which is fixed per connection (STANDBY under
\* backup_fec, ACTIVE otherwise); choosing it per poll over-approximates.
EnvValidationPoll ==
  /\ ~destroyed
  /\ Ticking
  /\ slot.state = "Validating"
  /\ xqcSideActive
  /\ \E t \in {"Active", "Standby"} :
       Fire("VALIDATION_OK", [NoCtx EXCEPT !.target = t])
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, conn, mpReady, mp,
                 mpCredit, closeCount, xqcSideActive, pendingXqcRemoval,
                 nextXqcId, abandonCount, releaseObligations, pendingRelease,
                 dupCount>>

\* path_fsm_tick_confirm_stable once the 30 s window has elapsed.
EnvStableConfirm ==
  /\ ~destroyed
  /\ Ticking
  /\ slot.state \in {"Active", "Standby"}
  /\ slot.stableArmed
  /\ slot.live
  /\ Fire("STABLE_TICK", [NoCtx EXCEPT !.reached = TRUE])
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, conn, mpReady, mp,
                 mpCredit, closeCount, xqcSideActive, pendingXqcRemoval,
                 nextXqcId, abandonCount, releaseObligations, pendingRelease,
                 dupCount>>

\* mqvpn_client_reactivate_path and reactivate_slot_eligible
\* (mqvpn_client.c:3549-3594): ESTABLISHED and multipath ready, then an
\* attached slot with no live xquic path in one of the three retry states.
\* Called with the current handle (see Platform and API).
ApiManualReactivate ==
  /\ ~destroyed
  /\ Ticking
  /\ ~slot.live
  /\ slot.attached
  /\ slot.state \in {"ClosedRecoverable", "CreateWait", "Degraded"}
  /\ Activation("MANUAL_REACTIVATE")
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, conn, mpReady, mp,
                 mpCredit, closeCount, pendingXqcRemoval, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

--------------------------------------------------------------------------------
\* Abstract xquic

\* The slot's path passes validation on the xquic side (PATH_RESPONSE).
EnvXqcValidate ==
  /\ ~destroyed
  /\ conn \in ConnUp
  /\ slot.live
  /\ ~xqcSideActive
  /\ <<slot.xqcId, inc>> \notin pendingXqcRemoval
  /\ xqcSideActive' = TRUE
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed, conn,
                 mpReady, mp, mpCredit, closeCount, pendingXqcRemoval,
                 nextXqcId, abandonCount, releaseObligations, pendingRelease,
                 dupCount>>

\* xquic abandons a path on its own when its validation times out
\* (xqc_path_validation_on_retx, xqc_multipath.c:460-484): multipath only,
\* and only a path that is still validating, so never an xquic-ACTIVE one.
\* Bounded and not fair.
EnvXqcSpontaneousAbandon ==
  /\ ~destroyed
  /\ conn \in ConnUp
  /\ mp
  /\ ~xqcSideActive
  /\ slot.live
  /\ abandonCount < AbandonCap
  /\ <<slot.xqcId, inc>> \notin pendingXqcRemoval
  /\ pendingXqcRemoval' = pendingXqcRemoval \cup {<<slot.xqcId, inc>>}
  /\ abandonCount' = abandonCount + 1
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed, conn,
                 mpReady, mp, mpCredit, closeCount, xqcSideActive, nextXqcId,
                 releaseObligations, pendingRelease, dupCount>>

\* cb_path_removed (mqvpn_client.c:2704-2721) -> find_path_by_xqc_id
\* (mqvpn_client.c:561-569) -> XQUIC_REMOVED. The lookup matches a live slot
\* with the same id only; the incarnation rides along as ghost data the real
\* lookup cannot see. This one-slot model does not exercise that guard: every
\* pending removal is the live slot's own (the inductive fact stated at
\* RemovalsBelongToCurrentIncarnation), so the lookup always matches.
DeliverRemoval ==
  /\ ~destroyed
  /\ conn \in ConnUp
  /\ \E e \in pendingXqcRemoval :
       /\ pendingXqcRemoval' = pendingXqcRemoval \ {e}
       /\ IF slot.live /\ slot.xqcId = e[1]
          THEN /\ slot' = Fsm!Step(slot, "XQUIC_REMOVED", NoCtx).slot
               /\ lastTrigger' = <<"XQUIC_REMOVED", e[2]>>
          ELSE UNCHANGED <<slot, lastTrigger>>
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, conn, mpReady, mp,
                 mpCredit, closeCount, xqcSideActive, nextXqcId, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

\* The two recovery routes of an orphan (a dropped slot whose PATH_ABANDON
\* failed or was never sent), exactly as xqc_timer_path_idle_timeout
\* (xqc_timer.c:137-161) splits them: the path idle timeout closes a path
\* only on a multipath connection and never the only xquic-ACTIVE path.
\* Here the slot's xquic-ACTIVE path is taken to be the only active one, the
\* one-slot reading that only DropLike departs from. Otherwise the
\* connection idles out (EnvConnIdleTimeout guards on the complement).
IdleReapable == mp /\ ~xqcSideActive

\* The path idle timeout reaps the orphan. This adds no state of its own
\* (DropLike's successful abandon reaches the same states); it is here for
\* fairness, so that an orphan is eventually reaped.
EnvPathIdleReap ==
  /\ ~destroyed
  /\ Orphan
  /\ IdleReapable
  /\ pendingXqcRemoval' = pendingXqcRemoval \cup {<<slot.xqcId, inc>>}
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed, conn,
                 mpReady, mp, mpCredit, closeCount, xqcSideActive, nextXqcId,
                 abandonCount, releaseObligations, pendingRelease, dupCount>>

\* The connection idles out. Not counted against ConnCloseCap: an orphan
\* exists at most once per incarnation (after the close, a reset clears live
\* or the client stays Closed), so this is bounded by MaxIncarnations.
EnvConnIdleTimeout ==
  /\ ~destroyed
  /\ Orphan
  /\ (~mp \/ xqcSideActive)   \* ~IdleReapable
  /\ ConnDown
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed,
                 mpReady, mp, mpCredit, closeCount, nextXqcId, abandonCount,
                 releaseObligations, pendingRelease, dupCount>>

--------------------------------------------------------------------------------
\* Platform and API
\*
\* Drop, remove and reactivate are called with the slot's current handle
\* only. Handles are never reused (mqvpn_client_add_path hands out
\* next_path_handle++), so find_path_by_handle finds no slot for an older
\* one and the call changes nothing (a stutter, omitted). A slot outside
\* CLOSED_FREE always has a handle: while inc = 0 the slot is FreshSlot.
\* Release calls may carry an older handle: DeliverRelease.

\* mqvpn_client_add_path (mqvpn_client.c:3362-3441): reuses only a
\* CLOSED_FREE slot (MQVPN_MAX_PATHS aside, a single-slot model has nowhere
\* to append), path_entry_init, a fresh handle, the transport installed,
\* then ADD. Covers the never-used slot too (inc = 0, FreshSlot).
ApiAdd ==
  /\ ~destroyed
  /\ inc < MaxIncarnations
  /\ slot.state = "ClosedFree"
  /\ slot' = Fsm!Step(FreshSlot, "ADD", NoCtx).slot
  /\ opsSet' = TRUE
  /\ inc' = inc + 1
  /\ lastTrigger' = <<"ADD", inc + 1>>
  /\ UNCHANGED <<releaseCount, destroyed, conn, mpReady, mp, mpCredit,
                 closeCount, xqcSideActive, pendingXqcRemoval, nextXqcId,
                 abandonCount, releaseObligations, pendingRelease, dupCount>>

\* mqvpn_client_on_platform_path_dropped / mqvpn_client_remove_path
\* (mqvpn_client.c:3456-3508): a live path is abandoned first, only when a
\* connection exists; xqc_conn_close_path may fail (multipath off, only
\* active path, closing: xqc_multipath.c:751-787) and the caller ignores
\* that. A failed abandon leaves the xquic path as it was. Then the event;
\* the platform now owes the release of an installed transport.
\*
\* The first of the two deliberate departures from the code (the other is
\* EnvValidationPoll's target): the abandon may succeed on the slot's
\* xquic-ACTIVE path, although xquic refuses to abandon the only ACTIVE path
\* (xqc_multipath.c:781-787). Success there stands for a connection on which
\* another path is active, the multi-slot case this one-slot model
\* abstracts. It is the only way the slot is reused on a live connection:
\* requiring ~xqcSideActive for success makes activation, CREATE_WAIT and
\* DEGRADED unreachable while TLC still reports no error (the vacuity gate
\* in formal/run_tlc.sh catches it).
DropLike(ev) ==
  /\ ~destroyed
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
  /\ UNCHANGED <<opsSet, inc, releaseCount, destroyed, conn, mpReady, mp,
                 mpCredit, closeCount, nextXqcId, abandonCount, pendingRelease,
                 dupCount>>

ApiDrop   == DropLike("PLATFORM_DROP")
ApiRemove == DropLike("REMOVE_API")

\* The platform stops I/O, closes its socket and reports the release.
PlatformRelease ==
  /\ ~destroyed
  /\ \E h \in releaseObligations :
       /\ releaseObligations' = releaseObligations \ {h}
       /\ pendingRelease' = pendingRelease \cup {h}
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed,
                 conn, mpReady, mp, mpCredit, closeCount, xqcSideActive,
                 pendingXqcRemoval, nextXqcId, abandonCount, dupCount>>

\* A release call for any handle ever issued, again or out of turn.
PlatformDupRelease ==
  /\ ~destroyed
  /\ dupCount < DupReleaseCap
  /\ \E h \in 1..inc :
       /\ pendingRelease' = pendingRelease \cup {h}
       /\ dupCount' = dupCount + 1
  /\ UNCHANGED <<slot, opsSet, inc, lastTrigger, releaseCount, destroyed,
                 conn, mpReady, mp, mpCredit, closeCount, xqcSideActive,
                 pendingXqcRemoval, nextXqcId, abandonCount,
                 releaseObligations>>

\* mqvpn_client_on_platform_path_released (mqvpn_client.c:3512-3535), its
\* guards in order: unknown/recycled handle (find_path_by_handle),
\* CLOSED_FREE (late duplicate), not CLOSED_DROPPED (refused), already
\* released or no transport; only then client_finalize_transport
\* (ops.release) and TRANSPORT_RELEASED.
DeliverRelease ==
  /\ ~destroyed
  /\ \E h \in pendingRelease :
       /\ pendingRelease' = pendingRelease \ {h}
       /\ IF /\ h = inc
             /\ slot.state = "ClosedDropped"
             /\ ~slot.released
             /\ opsSet
          THEN /\ opsSet' = FALSE
               /\ releaseCount' = [releaseCount EXCEPT ![h] = @ + 1]
               /\ slot' = Fsm!Step(slot, "TRANSPORT_RELEASED", NoCtx).slot
               \* Stamped with the delivered handle, not inc, so that
               \* StaleEventHarmless checks the handle guard.
               /\ lastTrigger' = <<"TRANSPORT_RELEASED", h>>
          ELSE UNCHANGED <<opsSet, releaseCount, slot, lastTrigger>>
  /\ UNCHANGED <<inc, destroyed, conn, mpReady, mp, mpCredit, closeCount,
                 xqcSideActive, pendingXqcRemoval, nextXqcId, abandonCount,
                 releaseObligations, dupCount>>

\* mqvpn_client_destroy (mqvpn_client.c:3123-3170) finalises every slot that
\* still owes a release, without setting the flag. client_finalize_transport
\* (mqvpn_client.c:964-981) calls ops.release only through the ops it
\* snapshots, which an earlier finalise already cleared: hence opsSet. Every
\* action requires ~destroyed: nothing happens after destroy.
EnvDestroy ==
  /\ ~destroyed
  /\ destroyed' = TRUE
  /\ IF ~slot.released /\ opsSet
     THEN /\ releaseCount' = [releaseCount EXCEPT ![inc] = @ + 1]
          /\ opsSet' = FALSE
     ELSE UNCHANGED <<releaseCount, opsSet>>
  /\ UNCHANGED <<slot, inc, lastTrigger, conn, mpReady, mp, mpCredit,
                 closeCount, xqcSideActive, pendingXqcRemoval, nextXqcId,
                 abandonCount, releaseObligations, pendingRelease, dupCount>>

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

\* A plain disjunction of the named actions, so that TLC names each step and
\* each coverage line after its action (ApiDrop and ApiRemove both as
\* DropLike); formal/run_tlc.sh fails when one of them never takes a step.
Next ==
  \/ ApiConnect \/ EnvMpReady \/ EnvTunnelReady \/ EnvEstablish
  \/ EnvConnClose \/ EnvReconnect \/ ApiDisconnectWhileReconnecting
  \/ EnvActivate \/ EnvRetryFire \/ EnvValidationPoll \/ EnvStableConfirm
  \/ ApiManualReactivate
  \/ EnvXqcValidate \/ EnvXqcSpontaneousAbandon \/ DeliverRemoval
  \/ EnvPathIdleReap \/ EnvConnIdleTimeout
  \/ ApiAdd \/ ApiDrop \/ ApiRemove
  \/ PlatformRelease \/ PlatformDupRelease \/ DeliverRelease
  \/ EnvDestroy

Spec == Init /\ [][Next]_vars

\* Fairness = the environment assumptions (formal/README.md). Weakly fair
\* are exactly: the two deliveries (DeliverRemoval, DeliverRelease), the
\* platform's release (PlatformRelease), connection progress (EnvMpReady,
\* EnvTunnelReady, EnvEstablish), reconnect attempts (EnvReconnect), armed
\* retries (EnvRetryFire) and the orphan's two routes (EnvPathIdleReap,
\* EnvConnIdleTimeout). Every other action may or may not happen; neither
\* liveness property needs a path to validate.
Fairness ==
  /\ WF_vars(DeliverRemoval)
  /\ WF_vars(PlatformRelease)
  /\ WF_vars(DeliverRelease)
  /\ WF_vars(EnvMpReady)
  /\ WF_vars(EnvTunnelReady)
  /\ WF_vars(EnvEstablish)
  /\ WF_vars(EnvReconnect)
  /\ WF_vars(EnvRetryFire)
  /\ WF_vars(EnvPathIdleReap)
  /\ WF_vars(EnvConnIdleTimeout)

LiveSpec == Spec /\ Fairness

--------------------------------------------------------------------------------
\* Properties

\* The types. nextXqcId \in 1..MaxXqcIds also checks that activation never
\* uses up the ids 1..MaxXqcIds.
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
  /\ nextXqcId \in 1..MaxXqcIds
  /\ abandonCount \in 0..AbandonCap
  /\ releaseObligations \subseteq 1..MaxIncarnations
  /\ pendingRelease \subseteq 1..MaxIncarnations
  /\ dupCount \in 0..DupReleaseCap

\* path_invariant_check holds in every reachable state.
InvPerState == Fsm!Legal(slot)

\* The C concretization rule, while not destroyed: a transport is installed
\* exactly while a release is owed.
OpsConsistent == ~destroyed => (opsSet <=> ~slot.released)

\* releaseCount counts finalisations (client_finalize_transport), which call
\* the optional ops.release. Each incarnation is finalised at most once ...
ReleaseAtMostOnce == \A i \in 1..MaxIncarnations : releaseCount[i] <= 1

\* ... every earlier incarnation was finalised before its slot was reused ...
EarlierIncarnationsReleased ==
  \A i \in 1..MaxIncarnations : i < inc => releaseCount[i] = 1

\* ... while not destroyed, the release flag of the current incarnation is
\* the ghost count ...
ReleasedMeansFinalized ==
  ~destroyed => (slot.released <=> (inc = 0 \/ releaseCount[inc] = 1))

\* ... and after destroy every installed transport was finalised.
NoLeakAtDestroy ==
  destroyed => \A i \in 1..MaxIncarnations : i <= inc => releaseCount[i] = 1

\* No removal notification outlives its incarnation. This rests on an
\* inductive fact: every pending removal is <<slot.xqcId, inc>> of the live
\* slot, so there is at most one. A removal is added only from the live slot
\* (an abandon, a spontaneous abandon, an idle reap). The slot's id and
\* incarnation change only while nothing is pending: activation and the
\* bootstrap start from a slot that is not live, a reset runs while the
\* connection is down (ConnDown drops every pending removal), and reuse
\* needs CLOSED_FREE, which is not live. live is cleared only by that reset
\* or by delivering the removal itself. So the id-keyed lookup of
\* cb_path_removed can never meet a removal of an earlier incarnation.
RemovalsBelongToCurrentIncarnation == \A e \in pendingXqcRemoval : e[2] = inc

\* A delayed event of an earlier incarnation never changes the slot: every
\* step that changes it carries the current incarnation. Fire stamps inc and
\* API calls use the current handle only, so what this checks is the handle
\* guard of DeliverRelease, which stamps the delivered handle. The removal
\* channel is covered structurally by RemovalsBelongToCurrentIncarnation.
StaleEventHarmless ==
  [][ slot' # slot => lastTrigger'[2] = inc' ]_vars

\* CLOSED_FREE is left only by reuse.
FreeQuiescent ==
  [][ (slot.state = "ClosedFree" /\ slot'.state # "ClosedFree")
        => inc' = inc + 1 ]_vars

\* A dropped slot reaches CLOSED_FREE, unless the client is destroyed or its
\* connection is closed for good (then a live xquic binding may stay behind
\* until destroy: README finding 2).
DroppedLeadsToFree ==
  (slot.state = "ClosedDropped")
    ~> (slot.state = "ClosedFree" \/ destroyed \/ conn = "Closed")

\* The retry states escape, unless the client is destroyed or its
\* connection is closed for good: to VALIDATING (a retry succeeds),
\* CLOSED_RECOVERABLE (the retry cap or a permanent failure), CLOSED_DROPPED
\* (drop or remove) or PENDING (the reset of a reconnect).
RetryEscapes ==
  (slot.state \in {"CreateWait", "Degraded"})
    ~> (slot.state \in {"Validating", "ClosedRecoverable", "ClosedDropped",
                        "Pending"}
        \/ destroyed \/ conn = "Closed")

================================================================================

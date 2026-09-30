---------------------------- MODULE PathSlotOracle ----------------------------
\* SPDX-License-Identifier: Apache-2.0
\* Copyright (c) 2026 mp0rta and mqvpn contributors
\*
\* Enumerates the one-step transition relation of PathSlotFsm!Step over every
\* invariant-legal abstract pre-state and every event/context class. TLC dumps
\* the rows (run_tlc.sh oracle), gen_oracle.py turns them into
\* path_slot_oracle.inc, and the C implementation is checked against that
\* table (tests/test_path_slot_oracle.c, formal/cbmc/).
\*
\* Abstract ids: a nonzero pre-state xqc_path_id is represented by 1 and the
\* context's new id by 2, so a post id of 0 / 1 / 2 reads as ZERO / OLD / NEW.

EXTENDS Naturals, FiniteSets, TLC

CONSTANT MaxRetries

Fsm == INSTANCE PathSlotFsm

NEW_ID == 2

Slots == [state : Fsm!States, attached : BOOLEAN, live : BOOLEAN,
          released : BOOLEAN, xqcId : {0, 1}, retries : 0..MaxRetries,
          retryArmed : BOOLEAN, stableArmed : BOOLEAN]

PreSet == {s \in Slots : Fsm!Legal(s)}

\* The 19 event/context classes. Every field is a string (TLC cannot compare
\* a string with a Boolean inside one set); a field an event does not read
\* is "-". reached is "reached" or "below".
Ctx(e, r, t, b) == [ev |-> e, result |-> r, target |-> t, reached |-> b]
EvCtx ==
     {Ctx(e, r, "-", "-") :
         e \in {"ACTIVATE", "RETRY", "MANUAL_REACTIVATE"}, r \in Fsm!Results}
  \cup {Ctx("VALIDATION_OK", "-", t, "-") : t \in {"Active", "Standby"}}
  \cup {Ctx(e, "-", "-", "-") :
         e \in {"XQUIC_REMOVED", "PLATFORM_DROP", "REMOVE_API", "ADD",
                "CONN_RESET", "TRANSPORT_RELEASED"}}
  \cup {Ctx("STABLE_TICK", "-", "-", b) : b \in {"reached", "below"}}

\* The caller's own slot writes that precede the dispatch, applied only where
\* the caller actually dispatches: mqvpn_client_add_path installs ops and ctx
\* on a CLOSED_FREE slot; mqvpn_client_on_platform_path_released finalises
\* (clears ops and ctx) only a CLOSED_DROPPED slot that still owes a release.
\* Every other row is the handler on its own. oracle_abs.h holds the C twin
\* (oracle_prefix_applies), cross-checked on every row. The ADD prefix is
\* deliberately not all of add_path's setup (path_entry_init, then handle,
\* name, address, net id, flags): ADD starts from every legal ClosedFree slot,
\* a superset of the one path_entry_init leaves.
CallerPrefix(pre, ev) ==
  \/ ev = "ADD" /\ pre.state = "ClosedFree"
  \/ ev = "TRANSPORT_RELEASED" /\ pre.state = "ClosedDropped" /\ ~pre.released

\* status is the public status of the post-state, the model's Projection:
\* the unit test compares the C slot's status with it.
Row(pre, c) ==
  LET out == Fsm!Step(pre, c.ev, [result |-> c.result, newId |-> NEW_ID,
                                  target |-> c.target,
                                  reached |-> c.reached = "reached"])
  IN [pre |-> pre, ev |-> c.ev, result |-> c.result, target |-> c.target,
      reached |-> c.reached, prefix |-> CallerPrefix(pre, c.ev),
      post |-> out.slot, status |-> Fsm!Projection(out.slot.state),
      fires |-> out.fires, notify |-> out.notify,
      retryUpd |-> out.retryUpd, stableUpd |-> out.stableUpd,
      retriesUpd |-> out.retriesUpd]

Rows == {Row(pre, c) : pre \in PreSet, c \in EvCtx}

ASSUME Cardinality(EvCtx) = 19
ASSUME PrintT(<<"oracle", "pre", Cardinality(PreSet), "rows", Cardinality(Rows)>>)
ASSUME Cardinality(Rows) = Cardinality(PreSet) * Cardinality(EvCtx)

VARIABLE row
Init == row \in Rows
Next == UNCHANGED row

\* Closure: every post-state is legal again.
PostLegal == Fsm!Legal(row.post)

================================================================================

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
"""Turn TLC's state graph of MqvpnPathSlot into path_slot_traces.inc.

Usage: gen_traces.py [--classes-only] <tlc-dot-dump> <output.inc>

The input is `-dump dot,actionlabels` of formal/MqvpnPathSlot.tla under
formal/mbt/MqvpnPathSlotMbt.cfg (formal/run_tlc.sh mbt). The output is a C
table of traces, each a path from Init replayed by the client-glue test
against the real client code, with the expected abstract post-state and
xquic commands of every step (formal/mbt/mbt_trace.h has the types).

The pipeline, each stage a hard error on anything it does not expect:
  1. parse: every node and edge line; an edge keeps its action label, and
     two edges with different labels between the same states stay two.
  2. decode: the model's nondeterministic choice of each edge is recovered
     from the pre/post difference (DECODE below); PlatformRelease and
     PlatformDupRelease stay in the graph but emit no step.
  3. compose: the code activates a pending slot inside add_path,
     cb_ready_to_create_path and client_release_path_hold, while the model
     takes a separate EnvActivate step. A state the code never rests in (a
     PENDING slot, multipath ready, the connection up, no hold, not
     destroyed: is_transient) is contracted: entering it by one of those
     three actions is fused with each EnvActivate out of it; every other
     edge out of it is dropped.
  4. realize: per client configuration (Init's mp / mpCredit / reqSched,
     plus backup_fec and reconnect), only the edges the code can take.
  5. cover: per configuration, breadth-first from Init; for each coverage
     class (the distinctions the code's guards and branches read) and each
     negative probe, the shortest witness. Traces are picked greedily
     (longest witness first, skipping classes already covered) and a trace
     that is a prefix of another is dropped.
The output is byte-for-byte deterministic for a given dump.
"""

import os
import re
import sys
from array import array
from collections import deque, namedtuple

HERE = os.path.dirname(os.path.abspath(__file__))
FORMAL = os.path.dirname(HERE)
sys.path.insert(0, FORMAL)
sys.path.insert(0, os.path.join(FORMAL, "oracle"))
import tla_values  # noqa: E402
from gen_oracle import STATE_C  # noqa: E402  (model state -> PATH_LC_*)

CFG = os.path.join(HERE, "MqvpnPathSlotMbt.cfg")
ORACLE_INC = os.path.join(FORMAL, "oracle", "path_slot_oracle.inc")
TLC_VERSION = "TLC2 2.19 (tlaplus v1.7.4, pinned by formal/run_tlc.sh)"
MBT_MAX_INC = 3          # mbt_trace.h
MAX_RETRIES = 6          # MaxRetries of the cfg; main() reads it
CONT_TRIES = 16          # continuation searches per class and configuration


def die(msg):
    sys.exit("gen_traces: " + msg)


# ─── Parsing ───

VARS = ("slot", "opsSet", "inc", "lastTrigger", "releaseCount", "destroyed",
        "conn", "mpReady", "mp", "mpCredit", "closeCount", "xqcSideActive",
        "pendingXqcRemoval", "nextXqcId", "abandonCount", "releaseObligations",
        "pendingRelease", "dupCount", "reqSched", "hold")
State = namedtuple("State", VARS)
SLOT_FIELDS = ("state", "attached", "live", "released", "xqcId", "retries",
               "retryArmed", "stableArmed")
Slot = namedtuple("Slot", SLOT_FIELDS)
Graph = namedtuple("Graph", "states labels src lab dst init")

CONN_UP = ("Connecting", "TunnelReady", "Established")
DOT_OTHER = ("strict digraph DiskGraph {", "nodesep=0.35;",
             "subgraph cluster_graph {", 'color="white";', "}")


def canon(v):
    """A parsed value in a hashable, totally ordered form (sets sorted)."""
    if isinstance(v, tla_values.Record):
        die("unexpected record %r" % (v,))
    if isinstance(v, frozenset):
        return tuple(sorted(canon(x) for x in v))
    if isinstance(v, tuple):
        return tuple(canon(x) for x in v)
    return v


_VALUES = {}


def value_of(name, text):
    key = (name, text)
    if key in _VALUES:
        return _VALUES[key]
    try:
        v = tla_values.parse(text)
    except ValueError as e:
        die("%s: %s" % (name, e))
    if name == "slot":
        if not isinstance(v, tla_values.Record) or set(v) != set(SLOT_FIELDS):
            die("slot is not a slot record: %r" % (v,))
        v = Slot(**v)
    else:
        v = canon(v)
    _VALUES[key] = v
    return v


def make_state(assigns):
    """State from (name, TLA text) pairs or a dict of them."""
    d = dict(assigns)
    if len(d) != len(VARS) or set(d) != set(VARS):
        die("state variables %s, expected %s" % (sorted(d), sorted(VARS)))
    return State(*[value_of(n, d[n]) for n in VARS])


def dot_unescape(s):
    # Split at the escaped backslashes first so that \\n stays \ + n.
    out = []
    for part in s.split("\\\\"):
        part = part.replace("\\n", "\n").replace('\\"', '"')
        if "\\" in part:
            die("unknown DOT escape in %r" % part[:60])
        out.append(part)
    return "\\".join(out)


def parse_node_line(line):
    fp, _, rest = line.partition(" ")
    end = rest.rfind('"')
    if not rest.startswith('[label="') or end < 8 \
            or rest[end + 1:] not in ("];", ",style = filled]"):  # TLC: plain / Init
        die("malformed node line: %r" % line[:80])
    text = dot_unescape(rest[8:end])
    if not text.startswith("/\\ "):
        die("node label does not start with /\\: %r" % text[:40])
    assigns = []
    for a in text[3:].split("\n/\\ "):
        name, sep, value = a.partition(" = ")
        if not sep:
            die("malformed assignment %r" % a[:60])
        assigns.append((name, value))
    return int(fp), assigns


def parse_dot(lines, expect_init=None):
    fp_ix, states, labels, lab_ix = {}, [], [], {}
    e_src, e_dst, e_lab = array("q"), array("q"), array("B")
    for line in lines:
        line = line.rstrip("\n")
        head, _, rest = line.partition(" ")
        if rest.startswith("-> "):
            dst, _, attrs = rest[3:].partition(" ")
            if not attrs.startswith('[label="'):
                die("edge without an action label: %r" % line[:80])
            label = attrs[8:attrs.index('"', 8)]
            if label not in lab_ix:
                lab_ix[label] = len(labels)
                labels.append(label)
            e_src.append(int(head))
            e_dst.append(int(dst))
            e_lab.append(lab_ix[label])
        elif rest.startswith('[label="'):
            fp, assigns = parse_node_line(line)
            s = make_state(assigns)
            if fp in fp_ix:
                if states[fp_ix[fp]] != s:
                    die("node %d printed twice with different states" % fp)
            else:
                fp_ix[fp] = len(states)
                states.append(s)
        elif line not in DOT_OTHER and not line.startswith("{rank = same;"):
            die("unexpected DOT line: %r" % line[:80])
    try:
        src = array("i", (fp_ix[f] for f in e_src))
        dst = array("i", (fp_ix[f] for f in e_dst))
    except KeyError as e:
        die("edge to an undeclared node %s" % e)
    has_in = bytearray(len(states))
    for s, d in zip(src, dst):
        if s != d:
            has_in[d] = 1
    init = sorted((i for i, s in enumerate(states)
                   if not has_in[i] and s.inc == 0 and s.conn == "Idle"),
                  key=states.__getitem__)
    if expect_init is not None and len(init) != expect_init:
        die("%d initial states, expected %d" % (len(init), expect_init))
    return Graph(states, labels, src, e_lab, dst, init)


# ─── Decoding the model's choices ───

Step = namedtuple("Step", "label op result arg_id arg_inc")
ENTRIES = ("ApiAdd", "EnvMpReady", "EnvTunnelReady")
SIMPLE = {"ApiConnect": "CONNECT", "EnvMpReady": "MP_READY",
          "EnvTunnelReady": "TUNNEL_READY", "EnvEstablish": "ESTABLISH",
          "ApiDisconnectWhileReconnecting": "DISCONNECT",
          "EnvStableConfirm": "STABLE", "EnvXqcValidate": "XQC_VALIDATE",
          "EnvDestroy": "DESTROY"}
SILENT = ("PlatformRelease", "PlatformDupRelease")


def is_transient(s):
    return (s.slot.state == "Pending" and s.mpReady and s.conn in CONN_UP
            and not s.hold and not s.destroyed)


def one(diff, what):
    if len(diff) != 1:
        die("%s: expected exactly one element, got %r" % (what, sorted(diff)))
    return next(iter(diff))


def activation(label, pre, post):
    """(result, new id) of an activation step (OnActivate / OnRetryTimer)."""
    if post.nextXqcId == pre.nextXqcId + 1:
        if post.slot.state != "Validating" or post.slot.xqcId != pre.nextXqcId:
            die("%s: a fresh id without a VALIDATING slot holding it" % label)
        return "OK", pre.nextXqcId
    if post.nextXqcId != pre.nextXqcId:
        die("%s: nextXqcId %d -> %d" % (label, pre.nextXqcId, post.nextXqcId))
    if post.slot.retries == pre.slot.retries + 1:
        return "TRANSIENT", 0
    # A TRANSIENT failure at saturated retries would look the same.
    if (post.slot.state == "ClosedRecoverable" and pre.slot.retries < MAX_RETRIES
            and post.slot.retries == pre.slot.retries):
        return "PERMANENT", 0
    die("%s: slot %r -> %r matches no activation result" % (label, pre.slot, post.slot))


def decode(label, pre, post):
    if label in SIMPLE:
        return Step(label, SIMPLE[label], "OK" if label == "ApiConnect" else "NONE", 0, 0)
    if label in SILENT:
        return Step(label, "", "NONE", 0, 0)
    if label in ("EnvActivate", "EnvRetryFire"):
        result, new_id = activation(label, pre, post)
        op = "ACTIVATE" if label == "EnvActivate" else "RETRY_FIRE"
        return Step(label, op, result, new_id, pre.inc)
    if label == "ApiManualReactivate":
        if post.slot == pre.slot and post.nextXqcId == pre.nextXqcId:
            return Step(label, "REACTIVATE", "TRANSIENT", 0, pre.inc)  # "FAIL"
        result, new_id = activation(label, pre, post)
        if result != "OK":
            die("ApiManualReactivate: a failure changed the slot")
        return Step(label, "REACTIVATE", result, new_id, pre.inc)
    if label == "ApiAdd":
        return Step(label, "ADD", "NONE", 0, post.inc)
    if label == "DropLike":
        op = {"PLATFORM_DROP": "DROP", "REMOVE_API": "REMOVE"}.get(post.lastTrigger[0])
        if op is None or post.lastTrigger[1] != pre.inc:
            die("DropLike: lastTrigger' %r" % (post.lastTrigger,))
        attempted = pre.slot.live and pre.conn in CONN_UP
        added = set(post.pendingXqcRemoval) - set(pre.pendingXqcRemoval)
        if added:
            if not attempted or added != {(pre.slot.xqcId, pre.inc)}:
                die("DropLike: abandon %r without a live slot" % (added,))
            return Step(label, op, "OK", 0, pre.inc)
        return Step(label, op, "FAIL" if attempted else "NONE", 0, pre.inc)
    if label in ("EnvConnClose", "EnvConnIdleTimeout"):
        if pre.conn not in CONN_UP or post.conn not in ("Reconnecting", "Closed"):
            die("%s: conn %s -> %s" % (label, pre.conn, post.conn))
        return Step(label, "PEER_CLOSE", "NONE", 0, 0)
    if label == "EnvReconnect":
        ok = post.conn == "Connecting"
        if pre.conn != "Reconnecting" or (not ok and post.conn != "Reconnecting") \
                or (ok and not pre.slot.attached):
            die("EnvReconnect: conn %s -> %s" % (pre.conn, post.conn))
        result = "OK" if ok else ("FAIL" if pre.slot.attached else "NONE")
        return Step(label, "RECONNECT_TICK", result, 0, 0)
    if label == "EnvValidationPoll":
        if post.slot.state not in ("Active", "Standby"):
            die("EnvValidationPoll: target %s" % post.slot.state)
        return Step(label, "POLL", "NONE", 0, 0)
    if label in ("EnvXqcSpontaneousAbandon", "EnvXqcRemoveActive", "EnvPathIdleReap"):
        e = one(set(post.pendingXqcRemoval) - set(pre.pendingXqcRemoval), label)
        return Step(label, "XQC_LOSE", "NONE", e[0], e[1])
    if label == "DeliverRemoval":
        e = one(set(pre.pendingXqcRemoval) - set(post.pendingXqcRemoval), label)
        return Step(label, "DELIVER_REMOVAL", "NONE", e[0], e[1])
    if label == "DeliverRelease":
        h = one(set(pre.pendingRelease) - set(post.pendingRelease), label)
        return Step(label, "DELIVER_RELEASE", "NONE", 0, h)
    die("undecodable action %r" % label)


# ─── Realization, coverage classes, expected commands ───

# Configuration bit = backup_fec * 2 + reconnect.
ALL, RC0, RC1, BF0, BF1 = 0b1111, 0b0101, 0b1010, 0b0011, 0b1100

Rec = namedtuple("Rec", "label op result arg_id arg_inc mask classes tags cmds rule")


def realize(step, post):
    """[(op, configuration mask)]: how the code takes this model step."""
    if step.label in ("EnvConnClose", "EnvConnIdleTimeout"):
        if post.conn == "Reconnecting":
            return [("PEER_CLOSE", RC1)]
        out = [("PEER_CLOSE", RC0)]
        if step.label == "EnvConnClose":
            out.append(("DISCONNECT", ALL))  # disconnect() closes in any cfg
        return out
    if step.label == "EnvReconnect":
        return [("RECONNECT_TICK", ALL), ("RECONNECT_API", ALL)]
    if step.label == "EnvValidationPoll":
        return [("POLL", BF0 if post.slot.state == "Active" else BF1)]
    return [(step.op, ALL)]


def fmt(v):
    return str(int(v)) if isinstance(v, bool) else str(v)


def k(action, **keys):
    return action + ":" + ",".join("%s=%s" % (a, fmt(b)) for a, b in keys.items())


def has_work(pre):
    s = pre.slot
    return (s.retries > 0 or s.retryArmed or pre.hold
            or s.state in ("Active", "Standby", "CreateWait", "Degraded",
                           "ClosedRecoverable", "ClosedDropped"))


def class_of(step, op, pre, post):
    """The coverage classes of a realised step: what the code's guards read."""
    L, s = step.label, pre.slot
    act = step.result.replace("NONE", "none") if L in ENTRIES else None
    if L == "ApiConnect":
        return [k(L, mp=pre.mp, reqSched=pre.reqSched)]
    if L == "EnvMpReady":
        return [k(L, hold=pre.hold, pending=s.state == "Pending", act=act)]
    if L == "EnvTunnelReady":
        if s.state == "Validating" and s.attached:
            return [k(L, validating=1, id0=s.xqcId == 0, act=act)]
        return [k(L, validating=0, act=act)]
    if L in ("EnvEstablish", "ApiDisconnectWhileReconnecting"):
        return [L]
    if L == "EnvConnClose":
        stim = "disconnect" if op == "DISCONNECT" else "peer"
        return [k(L, stage=pre.conn, stim=stim, result=post.conn)]
    if L == "EnvConnIdleTimeout":
        return [k(L, result=post.conn)]
    if L == "EnvReconnect":
        entry = "tick" if op == "RECONNECT_TICK" else "api"
        out = [k(L, entry=entry, attached=s.attached, ok=post.conn == "Connecting",
                 reqSched=pre.reqSched, work=has_work(pre))]
        if pre.hold and not post.hold:
            out.append(k(L, witness="reset_clears_hold", entry=entry))
        return out
    if L == "ApiAdd":
        out = [k(L, reuse=pre.inc > 0, hold=pre.hold, act=act)]
        if pre.conn in CONN_UP and pre.mpReady and pre.hold:
            out.append(k(L, witness="held_ready"))
        return out
    if L == "EnvRetryFire":
        capped = step.result == "TRANSIENT" and post.slot.state == "ClosedRecoverable"
        return [k(L, state=s.state, result=step.result, capped=capped)]
    if L == "EnvValidationPoll":
        return [k(L, target=post.slot.state)]
    if L == "EnvStableConfirm":
        # With retries 0 the confirmation has no effect on the abstract slot.
        return [k(L, state=s.state)] if s.retries > 0 else []
    if L == "ApiManualReactivate":
        return [k(L, state=s.state, result="OK" if step.result == "OK" else "FAIL")]
    if L == "DeliverRemoval":
        return [k(L, state=s.state)]
    if L == "DropLike":
        return [k(L, event=op.lower(), live=s.live, connup=pre.conn in CONN_UP,
                  id0=s.xqcId == 0, abandon=step.result.replace("NONE", "none"))]
    if L == "DeliverRelease":
        state = s.state if s.state in ("ClosedDropped", "ClosedFree") else "other"
        return [k(L, gen="cur" if step.arg_inc == pre.inc else "old", state=state,
                  owed=not s.released)]
    if L == "EnvDestroy":
        return [k(L, owed=not s.released and pre.opsSet, connup=pre.conn in CONN_UP)]
    if L in ("EnvActivate", "EnvXqcValidate", "EnvXqcSpontaneousAbandon",
             "EnvXqcRemoveActive", "EnvPathIdleReap") + SILENT:
        return []
    die("no coverage rule for %r" % L)


# Classes witnessed by a two-step pattern: (class, first-step tag, second-step tag).
def path_class(e1):
    return {"e1:release_then_ready": "EnvTunnelReady:witness=release_then_ready"}.get(
        e1, "EnvReconnect:witness=fail_then_tick_ok," + e1[len("e1:fail_then_tick_ok,"):])


def tags_of(step, op, pre, post):
    L, out = step.label, []
    if L == "EnvTunnelReady" and pre.hold and not pre.mpReady \
            and pre.slot.state == "Pending":
        # The hold is released while multipath is not ready: the next
        # readiness must activate the pending slot.
        out.append("e1:release_then_ready")
    if L == "EnvMpReady" and step.result != "NONE":
        out.append("e2:release_then_ready")
    if L == "EnvReconnect":
        if post.conn == "Reconnecting":
            # A failed reconnect must re-arm the timer: extend to a tick success.
            out.append("e1:fail_then_tick_ok,entry=%s,attached=%d" % (
                "tick" if op == "RECONNECT_TICK" else "api", pre.slot.attached))
        elif op == "RECONNECT_TICK":
            out.append("e2:fail_then_tick_ok")
    if L == "ApiDisconnectWhileReconnecting":
        out.append("probe:tick_after_disconnect")
    return out


def commands(step, op, pre):
    """(xqc_h3_connect, xqc_conn_create_path, xqc_conn_close_path, xqc_conn_close)."""
    connect = op == "CONNECT" or (op.startswith("RECONNECT_") and pre.slot.attached)
    create = op in ("ACTIVATE", "RETRY_FIRE", "REACTIVATE") or (
        step.label in ENTRIES and step.result != "NONE")
    close_path = op in ("DROP", "REMOVE") and pre.slot.live and pre.conn in CONN_UP
    conn_close = op == "DISCONNECT" and pre.conn in CONN_UP
    return (int(connect), int(create), int(close_path), int(conn_close))


def records(step, pre, post):
    out = []
    for op, mask in realize(step, post):
        rule = (op not in ("", "CONNECT", "RECONNECT_TICK", "RECONNECT_API")
                and pre.slot.state != post.slot.state)
        out.append(Rec(step.label, op, step.result, step.arg_id, step.arg_inc, mask,
                       tuple(class_of(step, op, pre, post)),
                       tuple(tags_of(step, op, pre, post)),
                       commands(step, op, pre), int(rule)))
    return out


# ─── Composition ───

class Composed:
    def __init__(self):
        self.src, self.rec, self.dst = array("i"), array("i"), array("i")
        self.recs, self.rec_ix, self.universe = [], {}, set()

    def add(self, s, step, d, states):
        for r in records(step, states[s], states[d]):
            if r not in self.rec_ix:
                self.rec_ix[r] = len(self.recs)
                self.recs.append(r)
                self.universe.update(r.classes)
                self.universe.update(path_class(t) for t in r.tags if t.startswith("e1:"))
            self.src.append(s)
            self.rec.append(self.rec_ix[r])
            self.dst.append(d)

    def edges(self):
        for s, r, d in zip(self.src, self.rec, self.dst):
            yield s, self.recs[r], d


def compose(g):
    S, labels = g.states, g.labels
    trans = bytearray(is_transient(s) for s in S)
    act_lab = labels.index("EnvActivate") if "EnvActivate" in labels else -1
    acts = {}
    for s, lab, d in zip(g.src, g.lab, g.dst):
        if lab == act_lab:
            if not trans[s]:
                die("EnvActivate out of a resting state")
            acts.setdefault(s, []).append((decode("EnvActivate", S[s], S[d]), d))
    c, dropped = Composed(), set()
    for s, lab, d in zip(g.src, g.lab, g.dst):
        if trans[s]:
            # Interleavings the code cannot take; kept only for the manifest.
            if lab != act_lab:
                step = decode(labels[lab], S[s], S[d])
                for r in records(step, S[s], S[d]):
                    dropped.update(r.classes)
            continue
        step = decode(labels[lab], S[s], S[d])
        if not trans[d]:
            c.add(s, step, d, S)
            continue
        if step.label not in ENTRIES:
            die("%s enters a transient state" % step.label)
        if d not in acts:
            die("a transient state without EnvActivate")
        for a, w in acts[d]:
            c.add(s, step._replace(result=a.result, arg_id=a.arg_id, arg_inc=a.arg_inc),
                  w, S)
    c.universe |= dropped
    return c


# ─── Negative probes: one guard each, the only thing that blocks ───

ELIGIBLE = ("ClosedRecoverable", "CreateWait", "Degraded")


def ticking(s):
    return s.conn == "Established" and s.mpReady


PROBES = [  # (name, op, predicate on the witness state)
    ("tick_retry", "PROBE_TICK", lambda s: s.slot.state in ("CreateWait", "Degraded")
        and s.slot.retryArmed and s.mpReady and s.conn in ("Connecting", "TunnelReady")),
    ("tick_poll", "PROBE_TICK", lambda s: s.slot.state == "Validating"
        and s.xqcSideActive and s.mpReady and s.conn in ("Connecting", "TunnelReady")),
    ("tick_hold", "PROBE_TICK", lambda s: s.slot.state == "Pending" and s.mpReady
        and s.hold and s.conn == "Connecting"),
    ("poll_id", "PROBE_POLL_ID", lambda s: ticking(s)
        and s.slot.state == "Validating" and not s.xqcSideActive),
    ("reactivate_conn", "PROBE_REACTIVATE", lambda s: s.mpReady
        and s.conn in ("Connecting", "TunnelReady") and not s.slot.live
        and s.slot.attached and s.slot.state in ELIGIBLE),
    ("reactivate_old_handle", "PROBE_REACTIVATE", lambda s: ticking(s) and s.inc >= 2
        and not s.slot.live and s.slot.attached and s.slot.state in ELIGIBLE),
    ("reactivate_ineligible", "PROBE_REACTIVATE", lambda s: ticking(s)
        and s.slot.state == "Validating"),
    ("removal_id", "PROBE_REMOVAL_ID", lambda s: s.slot.live and s.conn in CONN_UP),
    ("tick_after_disconnect", "PROBE_TICK_AFTER_DISCONNECT", None),  # edge-tagged
]
PROBE_OP = {name: op for name, op, _ in PROBES}


def probe_args(name, s):
    if name in ("poll_id", "removal_id"):
        return s.nextXqcId, 0       # an id xquic has not issued
    if name == "reactivate_old_handle":
        return 0, s.inc - 1
    return 0, s.inc


# ─── Search and selection ───

def csr(g, c):
    """Sort the composed edges by (source, record, destination content)."""
    rec_rank = array("i", [0]) * len(c.recs)
    for i, r in enumerate(sorted(range(len(c.recs)), key=c.recs.__getitem__)):
        rec_rank[r] = i
    order = sorted(range(len(g.states)), key=g.states.__getitem__)
    st_rank = array("i", [0]) * len(order)
    for i, s in enumerate(order):
        st_rank[s] = i
    if len(c.recs) >= 1 << 20 or len(order) >= 1 << 22:
        die("graph too large for the edge key")
    keys = [(s << 42) | (rec_rank[r] << 22) | st_rank[d]
            for s, r, d in zip(c.src, c.rec, c.dst)]
    keys.sort()
    # Edges with the same label between the same states are one edge.
    keys = [x for i, x in enumerate(keys) if i == 0 or keys[i - 1] != x]
    by_rank = array("i", [0]) * len(c.recs)
    for r, i in enumerate(rec_rank):
        by_rank[i] = r
    c.src = array("i", (x >> 42 for x in keys))
    c.rec = array("i", (by_rank[(x >> 22) & 0xFFFFF] for x in keys))
    c.dst = array("i", (order[x & 0x3FFFFF] for x in keys))
    off = array("i", [0]) * (len(g.states) + 1)
    for s in c.src:
        off[s + 1] += 1
    for i in range(len(g.states)):
        off[i + 1] += off[i]
    c.off = off


def bfs(g, c, init, bit, probe_bits):
    """class -> witness items (edge indices, then maybe a probe), shortest first."""
    N, recs, src, rec, dst, off = len(g.states), c.recs, c.src, c.rec, c.dst, c.off
    usable = bytearray(((r.mask >> bit) & 1) for r in recs)
    open_rec = bytearray(1 if (r.classes or r.tags) else 0 for r in recs)
    dist, par = array("i", [-1]) * N, array("i", [-1]) * N
    found, tries = {}, {}

    def path_to(u):
        items = []
        while u != init:
            items.append(par[u])
            u = src[par[u]]
        return items[::-1]

    def continuation(start, tag):
        seen, q = {start: -1}, deque([start])
        while q:
            u = q.popleft()
            for e in range(off[u], off[u + 1]):
                if not usable[rec[e]]:
                    continue
                if tag in recs[rec[e]].tags:
                    out = [e]
                    while u != start:
                        out.append(seen[u])
                        u = src[seen[u]]
                    return out[::-1]
                if dst[e] not in seen:
                    seen[dst[e]] = e
                    q.append(dst[e])
        return None

    def visit(e, u):
        r, done = recs[rec[e]], True
        for cl in r.classes:
            if cl not in found:
                found[cl] = path_to(u) + [e]
        for t in r.tags:
            if t == "probe:tick_after_disconnect":
                cl = "Probe:tick_after_disconnect"
                if cl not in found:
                    found[cl] = path_to(u) + [e, ("probe", "tick_after_disconnect", dst[e])]
            elif t.startswith("e1:"):
                cl = path_class(t)
                if cl in found or tries.get(cl, 0) >= CONT_TRIES:
                    continue
                tries[cl] = tries.get(cl, 0) + 1
                cont = continuation(dst[e], "e2:" + t[3:].split(",")[0])
                if cont is None:
                    done = False
                else:
                    found[cl] = path_to(u) + [e] + cont
        if done:
            open_rec[rec[e]] = 0

    dist[init] = 0
    q = deque([init])
    while q:
        u = q.popleft()
        pb = probe_bits[u]
        if pb:
            for j, (name, _, _) in enumerate(PROBES):
                if pb >> j & 1 and "Probe:" + name not in found:
                    found["Probe:" + name] = path_to(u) + [("probe", name, u)]
        du = dist[u] + 1
        for e in range(off[u], off[u + 1]):
            r = rec[e]
            if not usable[r]:
                continue
            if open_rec[r]:
                visit(e, u)
            v = dst[e]
            if dist[v] < 0:
                dist[v] = du
                par[v] = e
                q.append(v)
    return found


def configs(g):
    out = []
    for i in g.init:
        s = g.states[i]
        for bf in (0, 1):
            for rc in (0, 1):
                out.append(((int(s.mp), int(s.mpCredit), int(s.reqSched), bf, rc), i, bf * 2 + rc))
    return sorted(out)


def item_classes(c, items, own):
    out = {own}
    for it in items:
        if not isinstance(it, tuple):
            out.update(c.recs[c.rec[it]].classes)
    return out


def select(g, c):
    """[(cfg, items)] and the set of covered classes."""
    probe_bits = array("H", [0]) * len(g.states)
    for i, s in enumerate(g.states):
        if not s.destroyed:
            for j, (_, _, pred) in enumerate(PROBES):
                if pred is not None and pred(s):
                    probe_bits[i] |= 1 << j
    cfgs, best = configs(g), {}
    for o, (cfg, init, bit) in enumerate(cfgs):
        for cl, items in bfs(g, c, init, bit, probe_bits).items():
            if cl not in best or len(items) < best[cl][0]:
                best[cl] = (len(items), o, items)
    covered, chosen = set(), []
    for cl in sorted(best, key=lambda x: (-best[x][0], best[x][1], x)):
        if cl in covered:
            continue
        _, o, items = best[cl]
        chosen.append((cfgs[o][0], items))
        covered |= item_classes(c, items, cl)
    return chosen, covered


# ─── Output ───

CONN_C = {"Idle": "MBT_CONN_IDLE", "Connecting": "MBT_CONN_CONNECTING",
          "TunnelReady": "MBT_CONN_TUNNEL_READY", "Established": "MBT_CONN_ESTABLISHED",
          "Reconnecting": "MBT_CONN_RECONNECTING", "Closed": "MBT_CONN_CLOSED"}


def status_map():
    """Model state -> MBT_STATUS_*, read from the TLC-generated oracle table."""
    row = re.compile(r"^\s*\{\{PATH_LC_\w+(?:, \d+){7}\}, OEV_\w+, OCTX_\w+, \d+, "
                     r"\{(PATH_LC_\w+)(?:, \d+){7}\}, MQVPN_PATH_(\w+),")
    name = {v: k for k, v in STATE_C.items()}
    out = {}
    with open(ORACLE_INC, encoding="utf-8") as f:
        for line in f:
            m = row.match(line)
            if m:
                st, status = name[m.group(1)], "MBT_STATUS_" + m.group(2)
                if out.setdefault(st, status) != status:
                    die("oracle maps %s to two statuses" % st)
    if set(out) != set(STATE_C):
        die("oracle status map covers %s" % sorted(out))
    return out


def expect(s, status):
    """The expected-post-state fields of a step, from model state s."""
    sl, rc = s.slot, s.releaseCount
    if len(rc) > MBT_MAX_INC:
        die("releaseCount has %d incarnations, mbt_trace.h holds %d" % (len(rc), MBT_MAX_INC))
    rc = tuple(rc) + (0,) * (MBT_MAX_INC - len(rc))
    return ("MBT_ST_" + STATE_C[sl.state][len("PATH_LC_"):], int(sl.attached),
            int(sl.live), int(sl.released), sl.retries, int(sl.retryArmed),
            int(sl.stableArmed), sl.xqcId, CONN_C[s.conn], int(s.mpReady),
            int(s.hold), int(s.opsSet), status[sl.state], rc)


def trace_steps(g, c, items, status):
    out = []
    for it in items:
        if isinstance(it, tuple):
            _, name, u = it
            s = g.states[u]
            arg_id, arg_inc = probe_args(name, s)
            out.append(("MBT_" + PROBE_OP[name], "MBT_RES_NONE", arg_id, arg_inc)
                       + expect(s, status) + (0, 0, 0, 0, 0))
            continue
        r = c.recs[c.rec[it]]
        if not r.op:
            continue
        out.append(("MBT_OP_" + r.op, "MBT_RES_" + r.result, r.arg_id, r.arg_inc)
                   + expect(g.states[c.dst[it]], status) + r.cmds + (r.rule,))
    return tuple(out)


def build(g, require=True):
    c = compose(g)
    csr(g, c)
    chosen, covered = select(g, c)
    status = status_map()
    seqs = {(cfg, trace_steps(g, c, items, status)) for cfg, items in chosen}
    traces = sorted(t for t in seqs if not any(
        o[0] == t[0] and len(o[1]) > len(t[1]) and o[1][:len(t[1])] == t[1] for o in seqs))
    universe = c.universe | {"Probe:" + p[0] for p in PROBES}
    if require:
        missing = [cl for cl in REQUIRED if cl not in covered]
        for entry in ("tick", "api"):
            if not any(cl.startswith("EnvReconnect:entry=%s," % entry)
                       and cl.endswith(",work=1") for cl in covered):
                missing.append("EnvReconnect:entry=%s,...,work=1" % entry)
        if missing:
            die("required classes not covered: %s" % ", ".join(missing))
    return traces, sorted(covered), sorted(universe - covered)


# The spec table's classes whose key values it enumerates outright. Those the
# model never reaches are listed in the header.
SPEC_ENUMERATED = (
    ["DeliverRemoval:state=" + x for x in ("Validating", "Active", "Standby", "ClosedDropped")]
    + ["EnvRetryFire:state=%s,result=%s,capped=%d" % (st, r, cap)
       for st in ("CreateWait", "Degraded")
       for r, cap in (("OK", 0), ("TRANSIENT", 0), ("TRANSIENT", 1), ("PERMANENT", 0))]
    + ["ApiManualReactivate:state=%s,result=%s" % (st, r)
       for st in ELIGIBLE for r in ("OK", "FAIL")]
    + ["EnvStableConfirm:state=" + x for x in ("Active", "Standby")]
    + ["EnvValidationPoll:target=" + x for x in ("Active", "Standby")]
    + ["EnvConnClose:stage=%s,stim=%s,result=%s" % (st, stim, r) for st in CONN_UP
       for stim, r in (("peer", "Reconnecting"), ("peer", "Closed"), ("disconnect", "Closed"))]
    + ["EnvConnIdleTimeout:result=" + x for x in ("Reconnecting", "Closed")])

REQUIRED = (["ApiAdd:witness=held_ready", "EnvTunnelReady:witness=release_then_ready"]
            + ["EnvReconnect:witness=fail_then_tick_ok,entry=%s,attached=1" % e
               for e in ("tick", "api")]
            + ["EnvReconnect:witness=reset_clears_hold,entry=%s" % e for e in ("tick", "api")]
            + ["Probe:" + p[0] for p in PROBES])


def read_cfg():
    with open(CFG, encoding="utf-8") as f:
        consts = dict(re.findall(r"^CONSTANT\s+(\w+)\s*=\s*(\d+)\s*$", f.read(), flags=re.M))
    return {n: int(v) for n, v in consts.items()}


def render(traces, covered, excluded, consts):
    steps = [s for _, seq in traces for s in seq]
    if len(steps) > 0xFFFF:
        die("%d steps do not fit uint16_t" % len(steps))
    for s in steps:
        if not all(0 <= v <= 0xFF for v in s[2:4] + s[5:12] + s[13:16]):
            die("a step field does not fit uint8_t: %r" % (s,))
    out = ["// SPDX-License-Identifier: Apache-2.0",
           "// Copyright (c) 2026 mp0rta and mqvpn contributors", "",
           "/* GENERATED by formal/mbt/gen_traces.py from the TLC state graph of",
           " * formal/MqvpnPathSlot.tla under formal/mbt/MqvpnPathSlotMbt.cfg - do not",
           " * edit. Regenerate with `formal/run_tlc.sh mbt`.",
           " * %s; %s." % (TLC_VERSION, ", ".join("%s = %d" % kv for kv in sorted(consts.items()))),
           " * %d classes, %d traces, %d steps." % (len(covered), len(traces), len(steps)),
           " *", " * Covered classes:"]
    out += [" *   " + cl for cl in covered]
    out += [" *", " * Excluded as unrealizable (only on interleavings the code cannot take):"]
    out += [" *   " + cl for cl in excluded] or [" *   (none)"]
    out += [" *", " * Spec-table classes not reached in this model:"]
    out += [" *   " + cl for cl in sorted(set(SPEC_ENUMERATED) - set(covered))] or [" *   (none)"]
    out += [" */",
            "#define MBT_GEN_MAX_RETRIES %d" % consts["MaxRetries"],
            "#define MBT_N_STEPS %d" % len(steps),
            "#define MBT_N_TRACES %d" % len(traces),
            '_Static_assert(MBT_MAX_INC >= %d, "MBT_MAX_INC < MaxIncarnations");'
            % consts["MaxIncarnations"], "",
            "/* {op, result, arg_id, arg_inc, state, attached, live, released, retries,",
            " *  retry_armed, stable_armed, xqc_id, conn, mp_ready, hold, ops_set, status,",
            " *  release_count, cmd_connect, cmd_create_path, cmd_close_path,",
            " *  cmd_conn_close, path_event_rule} */",
            "static const mbt_step_t MBT_STEPS[] = {"]
    first, tab = 0, []
    for t, (cfg, seq) in enumerate(traces):
        out.append("    /* trace %d */" % t)
        for s in seq:
            out.append("    {%s, %s, %d, %d, %s, %d, %d, %d, %d, %d, %d, %d, %s, %d, %d, %d, "
                       "%s, {%s}, %d, %d, %d, %d, %d}," % (
                           s[:17] + (", ".join(map(str, s[17])),) + s[18:]))
        tab.append("    {{%d, %d, %d, %d, %d}, %d, %d}," % (cfg + (first, len(seq))))
        first += len(seq)
    out += ["};", "",
            "/* {{mp, mp_credit, req_sched, backup_fec, reconnect}, first, n} */",
            "static const mbt_trace_t MBT_TRACES[] = {"] + tab + ["};"]
    return "\n".join(out) + "\n"


def generate(g, require=True, consts=None):
    consts = consts or read_cfg()
    return render(*build(g, require), consts)


def main():
    global MAX_RETRIES
    args = sys.argv[1:]
    classes_only = args[:1] == ["--classes-only"]
    if classes_only:
        args = args[1:]
    if len(args) != 2:
        die("usage: gen_traces.py [--classes-only] <tlc-dot-dump> <output.inc>")
    consts = read_cfg()
    MAX_RETRIES = consts["MaxRetries"]
    if consts["MaxIncarnations"] > MBT_MAX_INC:
        die("MaxIncarnations %d > MBT_MAX_INC" % consts["MaxIncarnations"])
    with open(args[0], encoding="utf-8") as f:
        g = parse_dot(f, expect_init=8)
    traces, covered, excluded = build(g)
    if classes_only:
        print("\n".join(covered))
        return
    with open(args[1], "w", encoding="utf-8", newline="\n") as f:
        f.write(render(traces, covered, excluded, consts))


if __name__ == "__main__":
    main()

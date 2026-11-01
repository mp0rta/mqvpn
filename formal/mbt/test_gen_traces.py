#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
"""Unit tests of gen_traces.py and tla_values.py on hand-written DOT graphs.

Run: python3 -B -m unittest discover -s formal/mbt -p 'test_*.py' -v
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import gen_traces as gt  # noqa: E402
import tla_values  # noqa: E402


def B(v):
    return "TRUE" if v else "FALSE"


def slot(state="ClosedFree", attached=False, live=False, released=True,
         xqcId=0, retries=0, retryArmed=False, stableArmed=False):
    # TLC's own layout: one field per line, two-space indent.
    return ('[ state |-> "%s",\n  attached |-> %s,\n  live |-> %s,\n'
            '  released |-> %s,\n  xqcId |-> %d,\n  retries |-> %d,\n'
            '  retryArmed |-> %s,\n  stableArmed |-> %s ]'
            % (state, B(attached), B(live), B(released), xqcId, retries,
               B(retryArmed), B(stableArmed)))


BASE = {
    "xqcSideActive": "FALSE", "abandonCount": "0", "mp": "TRUE",
    "reqSched": "FALSE", "conn": '"Idle"', "pendingXqcRemoval": "{}",
    "dupCount": "0", "releaseCount": "<<0, 0, 0>>", "slot": slot(),
    "releaseObligations": "{}", "lastTrigger": '<<"NONE", 0>>',
    "mpCredit": "TRUE", "nextXqcId": "1", "inc": "0", "mpReady": "FALSE",
    "opsSet": "FALSE", "pendingRelease": "{}", "closeCount": "0",
    "destroyed": "FALSE", "hold": "FALSE",
}


def st(**kw):
    d = dict(BASE)
    for k, v in kw.items():
        if k not in d:
            raise KeyError(k)
        d[k] = v
    return d


def node(fp, s, init=False):
    text = "\n".join("/\\ %s = %s" % kv for kv in s.items())
    esc = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return '%d [label="%s"%s' % (fp, esc, ",style = filled]" if init else "];")


def edge(a, label, b):
    return '%d -> %d [label="%s",color="black",fontcolor="black"];' % (a, b, label)


def dot(nodes, edges):
    return (["strict digraph DiskGraph {", "nodesep=0.35;",
             "subgraph cluster_graph {", 'color="white";']
            + nodes + edges + ["{rank = same; 1;}", "}", "}"])


# A pending, attached slot of incarnation 1 (after ApiAdd).
PENDING = slot("Pending", attached=True, released=False)
ADDED = dict(slot=PENDING, opsSet="TRUE", inc="1",
             lastTrigger='<<"ADD", 1>>')


def parse(nodes, edges):
    return gt.parse_dot(dot(nodes, edges))


def composed_edges(g):
    c = gt.compose(g)
    gt.csr(g, c)  # drops repeated edges with the same label
    return [(g.states[s], rec, g.states[d]) for s, rec, d in c.edges()]


class TlaValues(unittest.TestCase):
    def test_tla_values(self):
        self.assertEqual(tla_values.parse("{<<1, 2>>, <<0, 3>>}"),
                         frozenset({(1, 2), (0, 3)}))
        self.assertEqual(tla_values.parse('<<"ADD", 1>>'), ("ADD", 1))
        self.assertEqual(tla_values.parse("[a |-> {}, b |-> <<0, 0, 0>>]"),
                         {"a": frozenset(), "b": (0, 0, 0)})
        v = tla_values.parse('{[x |-> 1, y |-> "s"], [x |-> 2, y |-> "t"]}')
        self.assertEqual(len(v), 2)
        self.assertIn(tla_values.Record(x=1, y="s"), v)
        self.assertEqual(tla_values.parse("<<>>"), ())
        self.assertIs(tla_values.parse("TRUE"), True)
        with self.assertRaises(ValueError):
            tla_values.parse("[a |-> 1, a |-> 2]")
        with self.assertRaises(ValueError):
            tla_values.parse("<<1, 2")

    def test_dot_node_line(self):
        # Shortened from a real TLC dump: \\ is a backslash, \n a newline,
        # \" a quote.
        line = ('-1851865055200899651 [label="/\\\\ xqcSideActive = FALSE\\n'
                '/\\\\ conn = \\"Idle\\"\\n/\\\\ slot = [ state |-> \\"ClosedFree\\",'
                '\\n  attached |-> FALSE ]",style = filled]')
        fp, assigns = gt.parse_node_line(line)
        self.assertEqual(fp, -1851865055200899651)
        self.assertEqual(assigns, [
            ("xqcSideActive", "FALSE"), ("conn", '"Idle"'),
            ("slot", '[ state |-> "ClosedFree",\n  attached |-> FALSE ]')])
        self.assertEqual(gt.dot_unescape('a\\\\nb\\"\\n'), 'a\\nb"\n')


class Decode(unittest.TestCase):
    def test_parallel_labels_kept(self):
        # An orphan whose abandon failed: the second drop's abandon succeeds
        # and the idle reap reach the same post-state.
        orphan = slot("ClosedDropped", live=True, released=False, xqcId=1)
        common = dict(slot=orphan, opsSet="TRUE", inc="1", conn='"Established"',
                      lastTrigger='<<"PLATFORM_DROP", 1>>', nextXqcId="2")
        g = parse([node(1, st(**common), init=True),
                   node(2, st(pendingXqcRemoval="{<<1, 1>>}", **common))],
                  [edge(1, "DropLike", 2), edge(1, "EnvPathIdleReap", 2),
                   edge(1, "DropLike", 2)])
        got = sorted((r.label, r.op, r.result) for _, r, _ in composed_edges(g))
        self.assertEqual(got, [("DropLike", "DROP", "OK"),
                               ("EnvPathIdleReap", "XQC_LOSE", "NONE")])

    def test_droplike_event_from_lasttrigger(self):
        pre = gt.make_state(st(**ADDED))
        post = gt.make_state(st(**dict(
            ADDED, slot=slot("ClosedDropped", released=False),
            lastTrigger='<<"REMOVE_API", 1>>')))
        step = gt.decode("DropLike", pre, post)
        self.assertEqual((step.op, step.result, step.arg_inc), ("REMOVE", "NONE", 1))

    def test_activation_choice(self):
        conn = dict(ADDED, conn='"Established"', mpReady="TRUE")
        pre = gt.make_state(st(**dict(conn, slot=slot(
            "CreateWait", attached=True, released=False, retries=1,
            retryArmed=True))))
        ok = gt.make_state(st(**dict(conn, nextXqcId="3", lastTrigger='<<"RETRY", 1>>',
                                     slot=slot("Validating", attached=True,
                                               live=True, released=False,
                                               xqcId=2, retries=1))))
        pre = pre._replace(nextXqcId=2)
        step = gt.decode("EnvRetryFire", pre, ok)
        self.assertEqual((step.op, step.result, step.arg_id), ("RETRY_FIRE", "OK", 2))
        cw = gt.make_state(st(**dict(conn, lastTrigger='<<"RETRY", 1>>', slot=slot(
            "CreateWait", attached=True, released=False, retries=2,
            retryArmed=True)))) ._replace(nextXqcId=2)
        self.assertEqual(gt.decode("EnvRetryFire", pre, cw).result, "TRANSIENT")
        cr = gt.make_state(st(**dict(conn, lastTrigger='<<"RETRY", 1>>', slot=slot(
            "ClosedRecoverable", attached=True, released=False, retries=1)))) \
            ._replace(nextXqcId=2)
        self.assertEqual(gt.decode("EnvRetryFire", pre, cr).result, "PERMANENT")
        # A failed manual reactivation leaves the slot as it was: one class,
        # realised as TRANSIENT.
        pre_cr = cr._replace(lastTrigger=("MANUAL_REACTIVATE", 1))
        step = gt.decode("ApiManualReactivate", pre_cr, pre_cr)
        self.assertEqual((step.op, step.result), ("REACTIVATE", "TRANSIENT"))
        cls = gt.class_of(step, "REACTIVATE", pre_cr, pre_cr)
        self.assertEqual(cls, ["ApiManualReactivate:state=ClosedRecoverable,result=FAIL"])

    def test_release_target(self):
        dropped = dict(slot=slot("ClosedDropped", released=False), opsSet="TRUE",
                       inc="2", lastTrigger='<<"PLATFORM_DROP", 2>>')
        pre = gt.make_state(st(pendingRelease="{1, 2}", **dropped))
        post = gt.make_state(st(pendingRelease="{2}", **dropped))
        step = gt.decode("DeliverRelease", pre, post)
        self.assertEqual((step.op, step.arg_inc), ("DELIVER_RELEASE", 1))
        self.assertEqual(gt.class_of(step, step.op, pre, post),
                         ["DeliverRelease:gen=old,state=ClosedDropped,owed=1"])
        # The platform's own release calls are graph edges but no output step.
        g = parse([node(1, st(**dropped), init=True),
                   node(2, st(pendingRelease="{2}", **dropped)),
                   node(3, st(pendingRelease="{1, 2}", dupCount="1", **dropped))],
                  [edge(1, "PlatformRelease", 2),
                   edge(2, "PlatformDupRelease", 3),
                   edge(3, "DeliverRelease", 2)])
        c = gt.compose(g)
        path = [k for k in range(len(c.src))]
        steps = gt.trace_steps(g, c, path, gt.status_map())
        self.assertEqual([s[0] for s in steps], ["MBT_OP_DELIVER_RELEASE"])

    def test_undecodable_edge_raises(self):
        a = gt.make_state(st(**ADDED))
        with self.assertRaises(SystemExit):
            gt.decode("NoSuchAction", a, a)
        # A validation poll whose post-state is neither ACTIVE nor STANDBY.
        with self.assertRaises(SystemExit):
            gt.decode("EnvValidationPoll", a, a)
        # A removal delivery that removes nothing.
        with self.assertRaises(SystemExit):
            gt.decode("DeliverRemoval", a, a)


class Composition(unittest.TestCase):
    def setUp(self):
        up = dict(conn='"Connecting"', mpReady="TRUE", nextXqcId="1")
        self.free = st(**up)
        self.trans = st(**dict(up, **ADDED))
        self.valid = st(**dict(up, **dict(
            ADDED, nextXqcId="2", lastTrigger='<<"ACTIVATE", 1>>',
            slot=slot("Validating", attached=True, live=True, released=False,
                      xqcId=1))))
        self.tready = st(**dict(self.trans, conn='"TunnelReady"'))

    def test_transient_composition(self):
        g = parse([node(1, self.free, init=True), node(2, self.trans),
                   node(3, self.valid), node(4, self.tready)],
                  [edge(1, "ApiAdd", 2), edge(2, "EnvActivate", 3),
                   edge(2, "EnvTunnelReady", 4)])
        got = composed_edges(g)
        self.assertEqual(len(got), 1)
        pre, rec, post = got[0]
        self.assertEqual((rec.label, rec.op, rec.result, rec.arg_id, rec.arg_inc),
                         ("ApiAdd", "ADD", "OK", 1, 1))
        self.assertEqual(post.slot.state, "Validating")
        self.assertEqual(rec.cmds, (0, 1, 0, 0))
        self.assertIn("ApiAdd:reuse=0,hold=0,act=OK", rec.classes)
        # Entering the transient state by any other action is an error.
        g = parse([node(1, dict(self.trans, mpReady="FALSE"), init=True),
                   node(2, self.trans)], [edge(1, "EnvXqcValidate", 2)])
        with self.assertRaises(SystemExit):
            gt.compose(g)

    def test_hold_state_not_transient(self):
        held = dict(self.trans, hold="TRUE")
        self.assertFalse(gt.is_transient(gt.make_state(held)))
        self.assertTrue(gt.is_transient(gt.make_state(self.trans)))
        g = parse([node(1, dict(self.free, hold="TRUE"), init=True),
                   node(2, held)], [edge(1, "ApiAdd", 2)])
        (pre, rec, post), = composed_edges(g)
        self.assertEqual((rec.op, rec.result, rec.cmds), ("ADD", "NONE", (0, 0, 0, 0)))
        self.assertIn("ApiAdd:witness=held_ready", rec.classes)


class Output(unittest.TestCase):
    def graph(self):
        idle = st()
        added = st(**ADDED)
        boot = dict(ADDED, conn='"Connecting"', xqcSideActive="TRUE",
                    lastTrigger='<<"BOOTSTRAP", 1>>',
                    slot=slot("Validating", attached=True, live=True,
                              released=False))
        ready = dict(boot, conn='"TunnelReady"', lastTrigger='<<"VALIDATION_OK", 1>>',
                     slot=slot("Active", attached=True, live=True,
                               released=False, stableArmed=True))
        est = dict(ready, conn='"Established"')
        gone = dict(ADDED, destroyed="TRUE", opsSet="FALSE",
                    releaseCount="<<1, 0, 0>>")
        return parse([node(10, idle, init=True), node(11, added), node(12, st(**boot)),
                      node(13, st(**ready)), node(14, st(**est)), node(15, st(**gone))],
                     [edge(10, "ApiAdd", 11), edge(11, "ApiConnect", 12),
                      edge(12, "EnvTunnelReady", 13), edge(13, "EnvEstablish", 14),
                      edge(11, "EnvDestroy", 15)])

    def test_determinism(self):
        a = gt.generate(self.graph(), require=False)
        b = gt.generate(self.graph(), require=False)
        self.assertEqual(a, b)
        self.assertIn("ApiConnect:mp=1,reqSched=0", a)
        self.assertIn("static const mbt_step_t MBT_STEPS[]", a)
        self.assertIn("static const mbt_trace_t MBT_TRACES[]", a)
        # The establish branch, the destroy branch and the removal-id probe
        # (on the bootstrapped live slot); their shared prefixes are dropped.
        self.assertIn("#define MBT_N_TRACES 3", a)
        self.assertIn(" *   Probe:removal_id\n", a)


if __name__ == "__main__":
    unittest.main()

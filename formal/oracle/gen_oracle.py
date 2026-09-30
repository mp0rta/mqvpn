#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
"""Turn a TLC state dump of PathSlotOracle into path_slot_oracle.inc.

Usage: gen_oracle.py <tlc-dump-file> <output.inc>

The dump holds one `row = [...]` record per distinct state. Records are read
by field name, never by position: TLC prints fields in the order their names
were first interned, which changes when the module is edited. Anything the
generator does not expect (an unknown field, value or enum name, a duplicated
row, a pre-state without exactly the 19 event/context classes) is a hard
error, so a format change in TLC cannot silently produce a wrong table. A
slot's retries is bounded by the MaxRetries PathSlotOracle.cfg sets. The
output is byte-for-byte deterministic for a given dump and set of inputs.
"""

import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FORMAL = os.path.dirname(HERE)
REPO = os.path.dirname(FORMAL)


def die(msg):
    sys.exit("gen_oracle: " + msg)


# Every file whose content determines the table; their hashes go into the
# header so a stale table is visible in review.
INPUTS = [
    "formal/PathSlotFsm.tla",
    "formal/oracle/PathSlotOracle.tla",
    "formal/oracle/PathSlotOracle.cfg",
    "formal/oracle/gen_oracle.py",
]

STATE_C = {
    "Pending": "PATH_LC_PENDING",
    "CreateWait": "PATH_LC_CREATE_WAIT",
    "Validating": "PATH_LC_VALIDATING",
    "Active": "PATH_LC_ACTIVE",
    "Standby": "PATH_LC_STANDBY",
    "Degraded": "PATH_LC_DEGRADED",
    "ClosedRecoverable": "PATH_LC_CLOSED_RECOVERABLE",
    "ClosedDropped": "PATH_LC_CLOSED_DROPPED",
    "ClosedFree": "PATH_LC_CLOSED_FREE",
}
STATES = list(STATE_C)
EVENTS = ["ACTIVATE", "RETRY", "VALIDATION_OK", "XQUIC_REMOVED",
          "MANUAL_REACTIVATE", "PLATFORM_DROP", "REMOVE_API", "ADD",
          "CONN_RESET", "TRANSPORT_RELEASED", "STABLE_TICK"]
# (result, target, reached) -> context class
CTX = {
    ("-", "-", "-"): "OCTX_NONE",
    ("OK", "-", "-"): "OCTX_OK",
    ("TRANSIENT", "-", "-"): "OCTX_TRANSIENT",
    ("PERMANENT", "-", "-"): "OCTX_PERMANENT",
    ("-", "Active", "-"): "OCTX_ACTIVE",
    ("-", "Standby", "-"): "OCTX_STANDBY",
    ("-", "-", "reached"): "OCTX_REACHED",
    ("-", "-", "below"): "OCTX_BELOW",
}
CTX_ORDER = list(CTX.values())
UPD = {"KEEP": "UPD_KEEP", "ZERO": "UPD_ZERO", "NOW": "UPD_NOW",
       "ARM": "UPD_ARM", "INC": "UPD_INC"}
# PathSlotFsm!Projection's values -> mqvpn_path_status_t (include/libmqvpn.h)
STATUS_C = {"PENDING": "MQVPN_PATH_PENDING", "ACTIVE": "MQVPN_PATH_ACTIVE",
            "STANDBY": "MQVPN_PATH_STANDBY", "DEGRADED": "MQVPN_PATH_DEGRADED",
            "CLOSED": "MQVPN_PATH_CLOSED"}
SLOT_FIELDS = ["state", "attached", "live", "released", "xqcId", "retries",
               "retryArmed", "stableArmed"]
ROW_FIELDS = ["pre", "ev", "result", "target", "reached", "prefix", "post",
              "status", "fires", "notify", "retryUpd", "stableUpd",
              "retriesUpd"]
N_EVCTX = 19
# The event/context classes every pre-state must have (as C constants): the
# same set the CBMC harness's ctx_valid() accepts.
EVCTX = sorted(
    [(e, c) for e in ("ACTIVATE", "RETRY", "MANUAL_REACTIVATE")
     for c in ("OCTX_OK", "OCTX_TRANSIENT", "OCTX_PERMANENT")]
    + [("VALIDATION_OK", c) for c in ("OCTX_ACTIVE", "OCTX_STANDBY")]
    + [(e, "OCTX_NONE") for e in ("XQUIC_REMOVED", "PLATFORM_DROP", "REMOVE_API",
                                   "ADD", "CONN_RESET", "TRANSPORT_RELEASED")]
    + [("STABLE_TICK", c) for c in ("OCTX_REACHED", "OCTX_BELOW")])
if len(EVCTX) != N_EVCTX:
    die("EVCTX has %d event/context classes, expected %d" % (len(EVCTX), N_EVCTX))


def is_int(v):
    # A TLA Boolean parses to a Python bool, which is also an int.
    return type(v) is int


def cfg_max_retries():
    with open(os.path.join(REPO, "formal/oracle/PathSlotOracle.cfg"),
              encoding="utf-8") as f:
        found = re.findall(r"^CONSTANTS?\s+MaxRetries\s*=\s*(\d+)\s*$",
                           f.read(), flags=re.M)
    if len(found) != 1:
        die("PathSlotOracle.cfg sets MaxRetries %d times, expected once"
            % len(found))
    return int(found[0])


TOKEN = re.compile(r'\s*(\[|\]|,|\|->|"[^"]*"|TRUE|FALSE|-?\d+|[A-Za-z_]\w*)')


def tokenize(text):
    pos, out = 0, []
    text = text.rstrip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m:
            die("cannot tokenize near: %r" % text[pos:pos + 40])
        out.append(m.group(1))
        pos = m.end()
    return out


def parse_value(toks, i):
    t = toks[i]
    if t == "[":
        rec, i = {}, i + 1
        while True:
            key = toks[i]
            if not re.fullmatch(r"[A-Za-z_]\w*", key) or toks[i + 1] != "|->":
                die("malformed record near %r" % key)
            if key in rec:
                die("duplicate field %r" % key)
            rec[key], i = parse_value(toks, i + 2)
            if toks[i] == ",":
                i += 1
            elif toks[i] == "]":
                return rec, i + 1
            else:
                die("unexpected token %r in record" % toks[i])
    if t.startswith('"'):
        return t[1:-1], i + 1
    if t == "TRUE":
        return True, i + 1
    if t == "FALSE":
        return False, i + 1
    if re.fullmatch(r"-?\d+", t):
        return int(t), i + 1
    die("unexpected token %r" % t)


def read_rows(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    rows = []
    for block in re.split(r"^State \d+:\s*$", text, flags=re.M)[1:]:
        block = block.strip()
        if not block.startswith("row = "):
            die("state block does not start with 'row = '")
        toks = tokenize(block[len("row = "):])
        row, end = parse_value(toks, 0)
        if end != len(toks):
            die("trailing tokens after a row")
        rows.append(row)
    if not rows:
        die("no rows in %s" % path)
    return rows


def check_keys(rec, fields, what):
    if set(rec) != set(fields):
        die("%s fields %s, expected %s" % (what, sorted(rec), sorted(fields)))


def check_slot(s, is_post, max_retries):
    check_keys(s, SLOT_FIELDS, "slot")
    if s["state"] not in STATE_C:
        die("unknown state %r" % s["state"])
    ids = (0, 1, 2) if is_post else (0, 1)
    if not is_int(s["xqcId"]) or s["xqcId"] not in ids:
        die("unexpected abstract id %r" % s["xqcId"])
    if not is_int(s["retries"]) or not 0 <= s["retries"] <= max_retries:
        die("retries %r outside 0..%d" % (s["retries"], max_retries))
    for b in ("attached", "live", "released", "retryArmed", "stableArmed"):
        if not isinstance(s[b], bool):
            die("field %s is not boolean" % b)


# Formats a slot check_slot has accepted.
def slot_c(s):
    return "{%s, %d, %d, %d, %d, %d, %d, %d}" % (
        STATE_C[s["state"]], s["attached"], s["live"], s["released"],
        s["xqcId"], s["retries"], s["retryArmed"], s["stableArmed"])


def slot_key(s):
    return (STATES.index(s["state"]), s["attached"], s["live"], s["released"],
            s["xqcId"], s["retries"], s["retryArmed"], s["stableArmed"])


def main():
    if len(sys.argv) != 3:
        die("usage: gen_oracle.py <tlc-dump> <output.inc>")
    rows = read_rows(sys.argv[1])
    cfg_retries = cfg_max_retries()

    max_retries = None
    keyed = {}
    for r in rows:
        check_keys(r, ROW_FIELDS, "row")
        check_slot(r["pre"], False, cfg_retries)
        check_slot(r["post"], True, cfg_retries)
        if r["ev"] not in EVENTS:
            die("unknown event %r" % r["ev"])
        ctx = CTX.get((r["result"], r["target"], r["reached"]))
        if ctx is None:
            die("unknown context %r" % ((r["result"], r["target"], r["reached"]),))
        if r["status"] not in STATUS_C:
            die("unknown public status %r" % (r["status"],))
        for u in ("retryUpd", "stableUpd", "retriesUpd"):
            if r[u] not in UPD:
                die("unknown update class %r" % r[u])
        for b in ("prefix", "fires"):
            if not isinstance(r[b], bool):
                die("field %s is not boolean: %r" % (b, r[b]))
        if not is_int(r["notify"]) or r["notify"] not in (0, 1, 2, 3):
            die("notify out of range: %r" % r["notify"])
        for s in (r["pre"], r["post"]):
            if max_retries is None or s["retries"] > max_retries:
                max_retries = s["retries"]
        key = (slot_key(r["pre"]), EVENTS.index(r["ev"]), CTX_ORDER.index(ctx))
        if key in keyed:
            die("duplicate row for %r" % (key,))
        keyed[key] = (r, ctx)

    pres = sorted({slot_key(r["pre"]): r["pre"] for r in rows}.items())
    for pk, _ in pres:
        got = sorted((r["ev"], c) for (k, _, _), (r, c) in keyed.items() if k == pk)
        if got != EVCTX:
            die("pre-state %r has event/context classes %r" % (pk, got))

    digests = []
    for rel in INPUTS:
        with open(os.path.join(REPO, rel), "rb") as f:
            digests.append("%s  %s" % (hashlib.sha256(f.read()).hexdigest(), rel))

    out = []
    # The repository's C file header (CONTRIBUTING.md section 1).
    out.append("// SPDX-License-Identifier: Apache-2.0")
    out.append("// Copyright (c) 2026 mp0rta and mqvpn contributors")
    out.append("")
    out.append("/* GENERATED by formal/oracle/gen_oracle.py from a TLC dump of")
    out.append(" * formal/oracle/PathSlotOracle.tla - do not edit. Regenerate with")
    out.append(" * `formal/run_tlc.sh oracle`. Inputs (sha256):")
    for d in digests:
        out.append(" *   " + d)
    out.append(" */")
    out.append("#define PATH_SLOT_ORACLE_MAX_RETRIES %d" % max_retries)
    out.append("#define PATH_SLOT_ORACLE_N_PRE %d" % len(pres))
    out.append("#define PATH_SLOT_ORACLE_N_EVCTX %d" % N_EVCTX)
    out.append("#define PATH_SLOT_ORACLE_N_ROWS %d" % len(keyed))
    out.append("")
    out.append("/* {state, attached, live, released, id, retries, retry_armed, stable_armed} */")
    out.append("static const oracle_slot_t PATH_SLOT_ORACLE_PRE[PATH_SLOT_ORACLE_N_PRE] = {")
    for _, s in pres:
        out.append("    %s," % slot_c(s))
    out.append("};")
    out.append("")
    out.append("/* {pre, event, ctx, prefix, post, status, fires, notify, retry_upd, stable_upd, retries_upd} */")
    out.append("static const oracle_row_t PATH_SLOT_ORACLE_ROWS[PATH_SLOT_ORACLE_N_ROWS] = {")
    for key in sorted(keyed):
        r, ctx = keyed[key]
        out.append("    {%s, OEV_%s, %s, %d, %s, %s, %d, %d, %s, %s, %s}," % (
            slot_c(r["pre"]), r["ev"], ctx, r["prefix"],
            slot_c(r["post"]), STATUS_C[r["status"]], r["fires"], r["notify"],
            UPD[r["retryUpd"]], UPD[r["stableUpd"]], UPD[r["retriesUpd"]]))
    out.append("};")

    with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()

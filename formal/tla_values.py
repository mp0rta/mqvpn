# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
"""Parse the TLA+ values TLC prints in its state dumps.

Shared by formal/oracle/gen_oracle.py and formal/mbt/gen_traces.py. Covers
exactly what the models print: records [a |-> v, ...], sets {a, b},
sequences / tuples <<a, b>>, strings, integers and Booleans, nested in any
way. A record parses to a Record (a hashable dict, so it can sit in a set),
a set to a frozenset, a tuple to a tuple. Anything else raises ValueError.
"""

import re

TOKEN = re.compile(
    r'\s*(<<|>>|\[|\]|\{|\}|,|\|->|"[^"]*"|TRUE|FALSE|-?\d+|[A-Za-z_]\w*)')
NAME = re.compile(r"[A-Za-z_]\w*")
INT = re.compile(r"-?\d+")


class Record(dict):
    """A TLA+ record. Never mutated after parsing, hence hashable."""

    def __hash__(self):
        return hash(frozenset(self.items()))


def tokenize(text):
    pos, out = 0, []
    text = text.rstrip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m:
            raise ValueError("cannot tokenize near: %r" % text[pos:pos + 40])
        out.append(m.group(1))
        pos = m.end()
    return out


def _items(toks, i, close):
    """Comma-separated values up to the closing token; returns (list, next)."""
    items = []
    if toks[i] == close:
        return items, i + 1
    while True:
        v, i = parse_value(toks, i)
        items.append(v)
        if toks[i] == ",":
            i += 1
        elif toks[i] == close:
            return items, i + 1
        else:
            raise ValueError("unexpected token %r, expected , or %s" % (toks[i], close))


def parse_value(toks, i):
    """Parse the value starting at toks[i]; returns (value, next index)."""
    if i >= len(toks):
        raise ValueError("value expected at end of input")
    t = toks[i]
    if t == "[":
        rec, i = Record(), i + 1
        while True:
            key = toks[i]
            if not NAME.fullmatch(key) or toks[i + 1] != "|->":
                raise ValueError("malformed record near %r" % key)
            if key in rec:
                raise ValueError("duplicate field %r" % key)
            rec[key], i = parse_value(toks, i + 2)
            if toks[i] == ",":
                i += 1
            elif toks[i] == "]":
                return rec, i + 1
            else:
                raise ValueError("unexpected token %r in record" % toks[i])
    if t == "{":
        items, i = _items(toks, i + 1, "}")
        return frozenset(items), i
    if t == "<<":
        items, i = _items(toks, i + 1, ">>")
        return tuple(items), i
    if t.startswith('"'):
        return t[1:-1], i + 1
    if t == "TRUE":
        return True, i + 1
    if t == "FALSE":
        return False, i + 1
    if INT.fullmatch(t):
        return int(t), i + 1
    raise ValueError("unexpected token %r" % t)


def parse(text):
    """Parse one complete value."""
    toks = tokenize(text)
    try:
        v, end = parse_value(toks, 0)
    except IndexError:
        raise ValueError("truncated value: %r" % text[:60]) from None
    if end != len(toks):
        raise ValueError("trailing tokens after a value: %r" % text[:60])
    return v

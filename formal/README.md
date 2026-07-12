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

## Property ↔ code map

(To be filled as the model lands.)

## Known abstractions

(To be filled as the model lands.)

## Counterexample log

None so far.

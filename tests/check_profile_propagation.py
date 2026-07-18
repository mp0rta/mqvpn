#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# Verifies MQVPN_LWIP_MOBILE_PROFILE reached every profile-consuming TU in a
# mobile-profile build (the _Static_assert cannot catch unpropagated TUs —
# they take the default branch and pass). Usage: check_profile_propagation.py <build-dir>
import json, sys

if len(sys.argv) != 2:
    raise SystemExit("usage: check_profile_propagation.py <build-dir>")
cc = json.load(open(f"{sys.argv[1]}/compile_commands.json"))
watch = ("third_party/lwip/", "src/hybrid/", "tests/test_tcp_lane", "fuzz/", "benchmarks/")
bad = [e["file"] for e in cc
       if any(w in e["file"] for w in watch)
       and "MQVPN_LWIP_MOBILE_PROFILE" not in e["command"]]
if bad:
    raise SystemExit(f"PROPAGATION FAIL: {bad}")
print("PASS: propagation")

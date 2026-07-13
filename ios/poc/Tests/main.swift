// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
import Foundation

var failures = 0
func check(_ cond: Bool, _ msg: String) { if !cond { failures += 1; print("FAIL: \(msg)") } }

// planReorder
check(ReorderSettings(enabled: false, profile: 4, ports: [443]).planReorder().rules.isEmpty,
      "disabled -> empty plan")
let plan = ReorderSettings(enabled: true, profile: 4, ports: [443, 443, 0, 70000, 5401]).planReorder()
check(plan.rules.map { $0.port } == [443, 5401], "dedupe + range filter")
check(plan.rules.allSatisfy { $0.proto == 17 && $0.profile == 4 }, "proto=17 + profile passthrough")
check(plan.warnings.contains { $0.contains("0") } && plan.warnings.contains { $0.contains("70000") },
      "out-of-range warnings")
let many = ReorderSettings(enabled: true, profile: 3, ports: Array(1000..<1020)).planReorder()
check(many.rules.count == 16 && many.warnings.contains { $0.contains("exceed 16") }, "cap at 16 + warning")

// isSavable
check(ReorderSettings(enabled: true, profile: 3, ports: []).isSavable == false, "enabled+no-ports unsavable")
check(ReorderSettings(enabled: true, profile: 3, ports: [443]).isSavable, "enabled+port savable")
check(ReorderSettings(enabled: false, profile: 3, ports: []).isSavable, "disabled always savable")

// parsePorts
let pp = ReorderSettings.parsePorts(" 443, 5401 ,x, ")
check(pp.ports == [443, 5401] && pp.warnings.contains { $0.contains("x") }, "parsePorts trim/skip/warn")

// providerConfiguration round-trip
let s = ReorderSettings(enabled: true, profile: 4, ports: [443, 5401])
check(ReorderSettings(providerConfiguration: s.toProviderConfiguration()) == s, "round-trip")

// exact-int validation
check(ReorderSettings.exactInt(NSNumber(value: true)) == nil, "reject bool NSNumber")
check(ReorderSettings.exactInt(NSNumber(value: 3.0)) == nil, "reject double-backed NSNumber")
check(ReorderSettings.exactInt(NSNumber(value: 3)) == 3, "accept int NSNumber")
let bad: [String: Any] = ["reorderEnabled": NSNumber(value: true),
                          "reorderProfile": NSNumber(value: 3.9),
                          "reorderPorts": [NSNumber(value: true), NSNumber(value: 443)]]
let parsed = ReorderSettings(providerConfiguration: bad)!
check(parsed.profile == 3 && parsed.ports == [443], "double profile clamps; bool port dropped")

// reorderEnableDecision (fail-closed)
check(ReorderSettings.reorderEnableDecision(ruleResults: [false, false]).enable == false, "all-fail -> disabled")
check(ReorderSettings.reorderEnableDecision(ruleResults: [false, true]) == (true, 1), "partial -> enabled, added=1")
check(ReorderSettings.reorderEnableDecision(ruleResults: []).enable == false, "no rules -> disabled")

// (snapshot + ingest/save tests appended by Tasks 3 and 7)

if failures == 0 { print("host tests: ALL PASS") } else { print("host tests: \(failures) FAILURES"); exit(1) }

---
layout: page
---

<script setup>
import { ref, computed } from 'vue'
import { usePerfData } from '../.vitepress/theme/composables/usePerfData'

const {
  loading, error,
  rawRows, failoverRows, aggregateRows,
  multipathSchedulerRows, udpSweepSummaryRows, udpSweepRows, ntnRows
} = usePerfData('/perf-data/weekly')

// Failover filter
const foSchedFilter = ref('wlb')
const filteredFailoverRows = computed(() => {
  return failoverRows.value.filter(r => {
    if (foSchedFilter.value && r.scheduler !== foSchedFilter.value) return false
    return true
  })
})

// Aggregation filters
const aggSchedFilter = ref('wlb')
const aggStreamsFilter = ref('64')
const filteredAggregateRows = computed(() => {
  return aggregateRows.value.filter(r => {
    if (aggSchedFilter.value && r.scheduler !== aggSchedFilter.value) return false
    if (aggStreamsFilter.value && String(r.streams) !== aggStreamsFilter.value) return false
    return true
  })
})

// UDP scheduler filter
const udpSchedFilter = ref('wlb')
const filteredUdpSweepRows = computed(() => {
  return udpSweepRows.value.filter(r => {
    if (udpSchedFilter.value && r.scheduler !== udpSchedFilter.value) return false
    return true
  })
})
</script>

# Weekly Benchmarks

<p class="page-desc">Extended benchmark suite run every Sunday at 3:00 UTC.<br>Includes all per-commit tests plus additional scenario-based tests.</p>

<div v-if="loading">Loading...</div>
<div v-else-if="error && !error.includes('404')" style="color: red;">Error: {{ error }}</div>
<div v-else-if="rawRows.length === 0 && multipathSchedulerRows.length === 0" class="no-data-block">
  No weekly data available yet. Weekly benchmarks run every Sunday at 3:00 UTC.
</div>
<template v-else>

## VPN Throughput (no emulation, netns)

<div v-if="rawRows.length === 0">No data.</div>
<table v-else>
  <thead>
    <tr>
      <th>Commit</th>
      <th>Date</th>
      <th>Dir</th>
      <th>Single-path (Mbps)</th>
      <th>Multipath MinRTT (Mbps)</th>
      <th>Multipath WLB (Mbps)</th>
    </tr>
  </thead>
  <tbody>
    <tr v-for="(r, i) in rawRows" :key="'raw-' + i">
      <td><code>{{ r.commit }}</code></td>
      <td>{{ r.date }}</td>
      <td>{{ r.dir }}</td>
      <td>{{ r.single }}</td>
      <td>{{ r.minrtt }}</td>
      <td>{{ r.wlb }}</td>
    </tr>
  </tbody>
</table>

## Failover

<div v-if="failoverRows.length === 0">No data.</div>
<template v-else>
<div class="filter-bar">
  <label>Scheduler: <select v-model="foSchedFilter"><option value="">All</option><option value="wlb">WLB</option><option value="minrtt">MinRTT</option></select></label>
</div>
<table>
  <thead><tr><th>Commit</th><th>Date</th><th>Scheduler</th><th>TTF (s)</th><th>TTR (s)</th><th>Pre-fault (Mbps)</th><th>Degraded (Mbps)</th><th>Post-recover (Mbps)</th></tr></thead>
  <tbody>
    <tr v-for="(r, i) in filteredFailoverRows" :key="'fo-' + i">
      <td><code>{{ r.commit }}</code></td><td>{{ r.date }}</td><td>{{ r.scheduler }}</td><td>{{ r.ttf }}</td><td>{{ r.ttr }}</td><td>{{ r.pre }}</td><td>{{ r.degraded }}</td><td>{{ r.post }}</td>
    </tr>
  </tbody>
</table>
</template>

## Bandwidth Aggregation

<div v-if="aggregateRows.length === 0">No data.</div>
<template v-else>
<div class="filter-bar">
  <label>Scheduler: <select v-model="aggSchedFilter"><option value="">All</option><option value="wlb">WLB</option><option value="minrtt">MinRTT</option></select></label>
  <label>Streams: <select v-model="aggStreamsFilter"><option value="">All</option><option value="1">1</option><option value="4">4</option><option value="16">16</option><option value="64">64</option></select></label>
</div>
<table>
  <thead><tr><th>Commit</th><th>Date</th><th>Scheduler</th><th>Streams</th><th>Single</th><th>Multi</th><th>Gain</th></tr></thead>
  <tbody>
    <tr v-for="(r, i) in filteredAggregateRows" :key="'agg-' + i">
      <td><code>{{ r.commit }}</code></td><td>{{ r.date }}</td><td>{{ r.scheduler }}</td><td>{{ r.streams }}</td><td>{{ r.single }} Mbps</td><td>{{ r.multi }} Mbps</td><td>{{ r.gain }}</td>
    </tr>
  </tbody>
</table>
</template>

## Multipath Scheduler Scenarios

<p class="section-desc">Compares WLB and MinRTT schedulers across 8 network scenarios with different delay/bandwidth/loss profiles. RTT = 2x one-way delay.</p>

<details class="scenario-details">
<summary>Scenario conditions</summary>

- **equal_paths** — A: 50Mbps/10ms, B: 50Mbps/10ms
- **asymmetric_bandwidth** — A: 100Mbps/5ms, B: 50Mbps/20ms
- **high_jitter** — A: 50Mbps/10ms±5ms, B: 50Mbps/10ms±5ms
- **asymmetric_jitter** — A: 50Mbps/10ms (stable), B: 50Mbps/10ms±8ms
- **lossy_path** — A: 50Mbps/10ms, B: 50Mbps/10ms/1% loss
- **realistic_mixed** — A: 100Mbps/5ms, B: 50Mbps/20ms±5ms/0.5% loss
- **mobile_dual_lte** — A: 50Mbps/30ms±10ms/0.5% loss, B: 30Mbps/50ms±15ms/1% loss
- **mobile_wifi_lte** — A: 80Mbps/5ms±2ms, B: 30Mbps/40ms±12ms/0.5% loss

</details>

<div v-if="multipathSchedulerRows.length === 0">No data.</div>
<table v-else>
  <thead>
    <tr>
      <th>Commit</th>
      <th>Date</th>
      <th>Scenario</th>
      <th>Single (Mbps)</th>
      <th>WLB (Mbps)</th>
      <th>MinRTT (Mbps)</th>
    </tr>
  </thead>
  <tbody>
    <tr v-for="(r, i) in multipathSchedulerRows" :key="'ms-' + i">
      <td><code>{{ r.commit }}</code></td>
      <td>{{ r.date }}</td>
      <td>{{ r.scenario }}</td>
      <td>{{ r.single }}</td>
      <td>{{ r.wlb }}</td>
      <td>{{ r.minrtt }}</td>
    </tr>
  </tbody>
</table>

## UDP Rate Sweep

<p class="section-desc">Sweeps UDP send rate from 200-380 Mbps to find the saturation point (loss > 5%). Payload: 1100B, DL direction.</p>

<div v-if="udpSweepSummaryRows.length === 0">No data.</div>
<template v-else>

**Saturation Points**

<table>
  <thead><tr><th>Commit</th><th>Date</th><th>Single (Mbps)</th><th>WLB (Mbps)</th><th>MinRTT (Mbps)</th></tr></thead>
  <tbody>
    <tr v-for="(r, i) in udpSweepSummaryRows" :key="'udps-' + i">
      <td><code>{{ r.commit }}</code></td><td>{{ r.date }}</td><td>{{ r.single_saturation }}</td><td>{{ r.wlb_saturation }}</td><td>{{ r.minrtt_saturation }}</td>
    </tr>
  </tbody>
</table>

**Sweep Detail**

<div class="filter-bar">
  <label>Condition: <select v-model="udpSchedFilter"><option value="">All</option><option value="single">Single</option><option value="wlb">WLB</option><option value="minrtt">MinRTT</option></select></label>
</div>
<table>
  <thead><tr><th>Commit</th><th>Rate (Mbps)</th><th>Throughput (Mbps)</th><th>Loss (%)</th><th>Jitter (ms)</th></tr></thead>
  <tbody>
    <tr v-for="(r, i) in filteredUdpSweepRows" :key="'udpd-' + i">
      <td><code>{{ r.commit }}</code></td><td>{{ r.rate }}</td><td>{{ r.throughput }}</td><td>{{ r.loss }}</td><td>{{ r.jitter }}</td>
    </tr>
  </tbody>
</table>

</template>

## NTN Satellite

<p class="section-desc">Tests multipath performance over Non-Terrestrial Network (satellite) link profiles based on 3GPP NTN specs and real-world Starlink measurements. RTT = 2x one-way delay.</p>

<details class="scenario-details">
<summary>Scenario conditions</summary>

- **lte_leo_starlink** — A: LTE 50Mbps/15ms±3ms/0.2% loss, B: LEO 100Mbps/25ms±8ms/0.5% loss
- **lte_leo_high_orbit** — A: LTE 50Mbps/15ms±3ms/0.2% loss, B: LEO 80Mbps/40ms±12ms/0.8% loss
- **lte_geo** — A: LTE 50Mbps/15ms±3ms/0.2% loss, B: GEO 20Mbps/300ms±5ms/0.2% loss
- **wifi_leo** — A: WiFi 80Mbps/3ms±1ms, B: LEO 100Mbps/25ms±8ms/0.5% loss
- **dual_leo** — A: LEO 100Mbps/25ms±8ms/0.5% loss, B: LEO 80Mbps/35ms±10ms/0.8% loss

</details>

<div v-if="ntnRows.length === 0">No data.</div>
<table v-else>
  <thead>
    <tr>
      <th>Commit</th>
      <th>Date</th>
      <th>Scenario</th>
      <th>Single (Mbps)</th>
      <th>WLB (Mbps)</th>
      <th>MinRTT (Mbps)</th>
    </tr>
  </thead>
  <tbody>
    <tr v-for="(r, i) in ntnRows" :key="'ntn-' + i">
      <td><code>{{ r.commit }}</code></td>
      <td>{{ r.date }}</td>
      <td>{{ r.scenario }}</td>
      <td>{{ r.single }}</td>
      <td>{{ r.wlb }}</td>
      <td>{{ r.minrtt }}</td>
    </tr>
  </tbody>
</table>

</template>

<style scoped>
.page-desc {
  font-size: 0.9em;
  color: var(--vp-c-text-2);
  margin-top: -8px;
}
.section-desc {
  font-size: 0.85em;
  color: var(--vp-c-text-3);
  margin-top: -8px;
}
table {
  border-collapse: collapse;
  width: 100%;
  margin: 1em 0;
}
th, td {
  border: 1px solid var(--vp-c-divider);
  padding: 6px 10px;
  text-align: left;
  white-space: nowrap;
}
th {
  background: var(--vp-c-bg-soft);
  font-weight: 600;
}
tr:hover td {
  background: var(--vp-c-bg-soft);
}
code {
  font-size: 0.85em;
}
.filter-bar {
  display: flex;
  gap: 16px;
  margin-bottom: 8px;
}
.filter-bar select {
  padding: 4px 8px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 4px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-1);
}
.no-data-block {
  color: var(--vp-c-text-3);
  font-style: italic;
  padding: 24px;
  text-align: center;
  border: 1px dashed var(--vp-c-divider);
  border-radius: 8px;
  margin: 16px 0;
}
</style>

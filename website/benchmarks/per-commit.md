---
layout: page
---

<script setup>
import { ref, computed } from 'vue'
import { usePerfData } from '../.vitepress/theme/composables/usePerfData'

const { loading, error, rawRows, failoverRows, aggregateRows } = usePerfData('/perf-data')

const foSchedFilter = ref('wlb')
const foPathFilter = ref('A')

const filteredFailoverRows = computed(() => {
  return failoverRows.value.filter(r => {
    if (foSchedFilter.value && r.scheduler !== foSchedFilter.value) return false
    if (foPathFilter.value && r.fault_path !== foPathFilter.value) return false
    return true
  })
})

const aggSchedFilter = ref('wlb')
const aggStreamsFilter = ref('64')

const filteredAggregateRows = computed(() => {
  return aggregateRows.value.filter(r => {
    if (aggSchedFilter.value && r.scheduler !== aggSchedFilter.value) return false
    if (aggStreamsFilter.value && String(r.streams) !== aggStreamsFilter.value) return false
    return true
  })
})
</script>

# Per-commit Benchmarks

<p class="page-desc">Benchmarks run on every push to main. Latest 10 results.<br>Environment: Proxmox VM, i9-13900H, 4 vCPU (pinned), Ubuntu 24.04.</p>

<ClientOnly>
<div v-if="loading">Loading...</div>
<div v-else-if="error" style="color: red;">Error: {{ error }}</div>
<template v-else>

## VPN Throughput (no emulation, netns)

<p class="section-desc">Measures mqvpn throughput over veth pairs without bandwidth/delay emulation.</p>

<div v-if="rawRows.length === 0">No data yet.</div>
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

<div v-if="failoverRows.length === 0">No data yet.</div>
<template v-else>
<div class="filter-bar">
  <label>Scheduler:
    <select v-model="foSchedFilter">
      <option value="">All</option>
      <option value="wlb">WLB</option>
      <option value="minrtt">MinRTT</option>
    </select>
  </label>
  <label>Fault Path:
    <select v-model="foPathFilter">
      <option value="">All</option>
      <option value="A">Path A</option>
      <option value="B">Path B</option>
    </select>
  </label>
</div>
<table>
  <thead>
    <tr>
      <th>Commit</th>
      <th>Date</th>
      <th>Scheduler</th>
      <th>Fault Path</th>
      <th>TTF (s)</th>
      <th>TTR (s)</th>
      <th>Pre-fault (Mbps)</th>
      <th>Degraded (Mbps)</th>
      <th>Post-recover (Mbps)</th>
    </tr>
  </thead>
  <tbody>
    <tr v-for="(r, i) in filteredFailoverRows" :key="'fo-' + i">
      <td><code>{{ r.commit }}</code></td>
      <td>{{ r.date }}</td>
      <td>{{ r.scheduler }}</td>
      <td>{{ r.fault_path }}</td>
      <td>{{ r.ttf }}</td>
      <td>{{ r.ttr }}</td>
      <td>{{ r.pre }}</td>
      <td>{{ r.degraded }}</td>
      <td>{{ r.post }}</td>
    </tr>
  </tbody>
</table>
</template>

## Bandwidth Aggregation

<div v-if="aggregateRows.length === 0">No data yet.</div>
<template v-else>

<div class="filter-bar">
  <label>Scheduler:
    <select v-model="aggSchedFilter">
      <option value="">All</option>
      <option value="wlb">WLB</option>
      <option value="minrtt">MinRTT</option>
    </select>
  </label>
  <label>Streams:
    <select v-model="aggStreamsFilter">
      <option value="">All</option>
      <option value="1">1</option>
      <option value="4">4</option>
      <option value="16">16</option>
      <option value="64">64</option>
    </select>
  </label>
</div>

<table>
  <thead>
    <tr>
      <th>Commit</th>
      <th>Date</th>
      <th>Scheduler</th>
      <th>Streams</th>
      <th>Single</th>
      <th>Multi</th>
      <th>Gain</th>
    </tr>
  </thead>
  <tbody>
    <tr v-for="(r, i) in filteredAggregateRows" :key="'agg-' + i">
      <td><code>{{ r.commit }}</code></td>
      <td>{{ r.date }}</td>
      <td>{{ r.scheduler }}</td>
      <td>{{ r.streams }}</td>
      <td>{{ r.single }} Mbps</td>
      <td>{{ r.multi }} Mbps</td>
      <td>{{ r.gain }}</td>
    </tr>
  </tbody>
</table>

</template>

</template>
</ClientOnly>

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
</style>

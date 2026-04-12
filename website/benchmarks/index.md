---
layout: page
---

<script setup>
import { computed } from 'vue'
import { usePerfData } from '../.vitepress/theme/composables/usePerfData'

const push = usePerfData('/perf-data', 1)
const weekly = usePerfData('/perf-data/weekly', 1)

const latestRaw = computed(() => push.rawRows.value[0] || null)
const latestFailover = computed(() => push.failoverRows.value[0] || null)
const latestAggregate = computed(() => {
  const rows = push.aggregateRows.value
  if (!rows.length) return null
  const best = rows.reduce((a, b) =>
    parseFloat(a.gain) > parseFloat(b.gain) ? a : b
  )
  return best
})

const latestNtn = computed(() => weekly.ntnRows.value[0] || null)
const latestMultipath = computed(() => weekly.multipathSchedulerRows.value[0] || null)
const latestFlowScaling = computed(() => weekly.flowScalingRows.value[0] || null)
const latestUdp = computed(() => weekly.udpSchedulerRows.value[0] || null)
</script>

# Benchmarks

Automated benchmark results from CI. Environment: Proxmox VM, i9-13900H, 4 vCPU (pinned), Ubuntu 24.04.

## Per-commit Results

Benchmarks run on every push to main.

<div v-if="push.loading.value">Loading...</div>
<div v-else-if="push.error.value" style="color: red;">{{ push.error.value }}</div>
<template v-else>

<div class="summary-grid">
  <div class="summary-card">
    <h3>VPN Throughput</h3>
    <div v-if="latestRaw">
      <div class="stat">{{ latestRaw.wlb }} <span class="unit">Mbps</span></div>
      <div class="label">WLB ({{ latestRaw.dir }})</div>
      <div class="meta"><code>{{ latestRaw.commit }}</code> &middot; {{ latestRaw.date }}</div>
    </div>
    <div v-else class="no-data">No data yet</div>
  </div>

  <div class="summary-card">
    <h3>Failover TTR</h3>
    <div v-if="latestFailover">
      <div class="stat">{{ latestFailover.wlb_ttr }}<span class="unit">s</span></div>
      <div class="label">WLB recovery time</div>
      <div class="meta"><code>{{ latestFailover.commit }}</code> &middot; {{ latestFailover.date }}</div>
    </div>
    <div v-else class="no-data">No data yet</div>
  </div>

  <div class="summary-card">
    <h3>Bandwidth Aggregation</h3>
    <div v-if="latestAggregate">
      <div class="stat">{{ latestAggregate.multi }} <span class="unit">Mbps</span></div>
      <div class="label">{{ latestAggregate.scheduler.toUpperCase() }}, {{ latestAggregate.streams }} streams &mdash; +{{ latestAggregate.gain }} vs single-path</div>
      <div class="label">Paths: 300Mbps + 80Mbps (theoretical max 380Mbps)</div>
      <div class="meta"><code>{{ latestAggregate.commit }}</code> &middot; {{ latestAggregate.date }}</div>
    </div>
    <div v-else class="no-data">No data yet</div>
  </div>
</div>

<p><a href="/benchmarks/per-commit">View all per-commit results &rarr;</a></p>

</template>

## Weekly Results

Extended benchmarks run every Sunday at 3:00 UTC.

<div v-if="weekly.loading.value">Loading...</div>
<div v-else-if="weekly.error.value && !weekly.error.value.includes('404')" style="color: red;">{{ weekly.error.value }}</div>
<template v-else>

<div v-if="weekly.items.value.length === 0" class="no-data-block">
  No weekly data available yet. Weekly benchmarks run every Sunday at 3:00 UTC.
</div>

<template v-else>
<div class="summary-grid">
  <div class="summary-card" v-if="latestMultipath">
    <h3>Multipath Scheduler</h3>
    <div class="stat">{{ latestMultipath.wlb }} <span class="unit">Mbps</span></div>
    <div class="label">WLB &middot; {{ latestMultipath.scenario }}</div>
  </div>

  <div class="summary-card" v-if="latestFlowScaling">
    <h3>Flow Scaling</h3>
    <div class="stat">{{ latestFlowScaling.mbps }} <span class="unit">Mbps</span></div>
    <div class="label">{{ latestFlowScaling.scheduler }} &middot; {{ latestFlowScaling.streams }} streams</div>
  </div>

  <div class="summary-card" v-if="latestUdp">
    <h3>UDP Scheduler</h3>
    <div class="stat">{{ latestUdp.mbps }} <span class="unit">Mbps</span></div>
    <div class="label">{{ latestUdp.scheduler }} &middot; {{ latestUdp.scenario }}</div>
  </div>

  <div class="summary-card" v-if="latestNtn">
    <h3>NTN Satellite</h3>
    <div class="stat">{{ latestNtn.wlb }} <span class="unit">Mbps</span></div>
    <div class="label">WLB &middot; {{ latestNtn.scenario }}</div>
  </div>
</div>
</template>

<p><a href="/benchmarks/weekly">View all weekly results &rarr;</a></p>

</template>

<style scoped>
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin: 16px 0;
}
.summary-card {
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  padding: 16px;
}
.summary-card h3 {
  margin: 0 0 8px 0;
  font-size: 0.9em;
  color: var(--vp-c-text-2);
}
.stat {
  font-size: 1.8em;
  font-weight: 700;
  line-height: 1.2;
}
.unit {
  font-size: 0.5em;
  font-weight: 400;
  color: var(--vp-c-text-2);
}
.label {
  font-size: 0.85em;
  color: var(--vp-c-text-2);
  margin-top: 4px;
}
.meta {
  font-size: 0.75em;
  color: var(--vp-c-text-3);
  margin-top: 6px;
}
.no-data {
  color: var(--vp-c-text-3);
  font-style: italic;
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
code {
  font-size: 0.85em;
}
</style>

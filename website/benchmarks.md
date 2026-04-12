---
layout: page
---

<script setup>
import { ref, onMounted } from 'vue'

const loading = ref(true)
const error = ref('')

const rawRows = ref([])
const failoverRows = ref([])
const aggregateRows = ref([])

function fmtDate(ts) {
  return new Date(ts).toISOString().slice(0, 10)
}

function fmtCommit(c) {
  return c ? c.slice(0, 7) : '?'
}

function fmtNum(v, digits = 1) {
  if (v == null) return '-'
  return Number(v).toFixed(digits)
}

async function fetchJson(url) {
  const res = await fetch(url)
  if (!res.ok) throw new Error(`${url}: ${res.status}`)
  return res.json()
}

onMounted(async () => {
  try {
    const index = await fetchJson('/perf-data/index.json')
    const entries = index.slice(0, 10)

    const allData = []
    for (const entry of entries) {
      for (const file of entry.files || []) {
        const data = await fetchJson(`/perf-data/${file}`)
        allData.push({ commit: entry.commit, timestamp: entry.timestamp, data })
      }
    }

    for (const item of allData) {
      const { commit, timestamp, data } = item
      const test = data.test

      if (test === 'raw_throughput') {
        for (const dir of Object.keys(data.results || {})) {
          const r = data.results[dir]
          const overhead = data.overhead_pct?.[dir]?.multipath_wlb
          rawRows.value.push({
            commit: fmtCommit(commit),
            date: fmtDate(timestamp),
            dir,
            direct: fmtNum(r.direct_mbps),
            single: fmtNum(r.single_path_mbps),
            minrtt: fmtNum(r.multipath_minrtt_mbps),
            wlb: fmtNum(r.multipath_wlb_mbps),
            overhead: fmtNum(overhead) + '%',
          })
        }
      } else if (test === 'failover') {
        const w = data.results?.wlb || {}
        const m = data.results?.minrtt || {}
        failoverRows.value.push({
          commit: fmtCommit(commit),
          date: fmtDate(timestamp),
          wlb_ttr: fmtNum(w.ttr_sec, 2),
          minrtt_ttr: fmtNum(m.ttr_sec, 2),
          wlb_pre: fmtNum(w.pre_fault_avg_mbps),
          minrtt_pre: fmtNum(m.pre_fault_avg_mbps),
        })
      } else if (test === 'aggregate') {
        for (const sched of Object.keys(data.results || {})) {
          const arr = data.results[sched]
          if (!Array.isArray(arr)) continue
          for (const r of arr) {
            aggregateRows.value.push({
              commit: fmtCommit(commit),
              date: fmtDate(timestamp),
              scheduler: sched,
              streams: r.streams,
              single: fmtNum(r.single_path_mbps),
              multi: fmtNum(r.multipath_mbps),
              gain: fmtNum(r.gain_pct) + '%',
            })
          }
        }
      }
    }
  } catch (e) {
    error.value = e.message || 'Failed to load benchmark data.'
  } finally {
    loading.value = false
  }
})
</script>

# Benchmarks

Automated benchmark results from CI.

<div v-if="loading">Loading...</div>
<div v-else-if="error" style="color: red;">Error: {{ error }}</div>
<template v-else>

## Raw Throughput (TCP)

<div v-if="rawRows.length === 0">No data yet.</div>
<table v-else>
  <thead>
    <tr>
      <th>Commit</th>
      <th>Date</th>
      <th>Dir</th>
      <th>Direct</th>
      <th>Single</th>
      <th>MinRTT</th>
      <th>WLB</th>
      <th>Overhead</th>
    </tr>
  </thead>
  <tbody>
    <tr v-for="(r, i) in rawRows" :key="'raw-' + i">
      <td><code>{{ r.commit }}</code></td>
      <td>{{ r.date }}</td>
      <td>{{ r.dir }}</td>
      <td>{{ r.direct }}</td>
      <td>{{ r.single }}</td>
      <td>{{ r.minrtt }}</td>
      <td>{{ r.wlb }}</td>
      <td>{{ r.overhead }}</td>
    </tr>
  </tbody>
</table>

## Failover TTR

<div v-if="failoverRows.length === 0">No data yet.</div>
<table v-else>
  <thead>
    <tr>
      <th>Commit</th>
      <th>Date</th>
      <th>WLB TTR</th>
      <th>MinRTT TTR</th>
      <th>WLB Pre-fault</th>
      <th>MinRTT Pre-fault</th>
    </tr>
  </thead>
  <tbody>
    <tr v-for="(r, i) in failoverRows" :key="'fo-' + i">
      <td><code>{{ r.commit }}</code></td>
      <td>{{ r.date }}</td>
      <td>{{ r.wlb_ttr }}s</td>
      <td>{{ r.minrtt_ttr }}s</td>
      <td>{{ r.wlb_pre }} Mbps</td>
      <td>{{ r.minrtt_pre }} Mbps</td>
    </tr>
  </tbody>
</table>

## Bandwidth Aggregation

<div v-if="aggregateRows.length === 0">No data yet.</div>
<table v-else>
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
    <tr v-for="(r, i) in aggregateRows" :key="'agg-' + i">
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

<style scoped>
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
</style>

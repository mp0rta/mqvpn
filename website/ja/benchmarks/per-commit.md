---
layout: page
---

<script setup>
import { ref, computed } from 'vue'
import { usePerfData } from '../../.vitepress/theme/composables/usePerfData'

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

# コミットごとのベンチマーク

<p class="page-desc">main へのプッシュごとに実行。最新 10 件の結果。<br>環境: Proxmox VM, i9-13900H, 4 vCPU（ピニング）, Ubuntu 24.04</p>

<ClientOnly>
<div v-if="loading">読み込み中...</div>
<div v-else-if="error" style="color: red;">エラー: {{ error }}</div>
<template v-else>

## VPN スループット（エミュレーションなし、netns）

<p class="section-desc">帯域/遅延エミュレーションなしの veth ペアで mqvpn のスループットを計測。</p>

<div v-if="rawRows.length === 0">データがありません。</div>
<table v-else>
  <thead>
    <tr>
      <th>コミット</th>
      <th>日付</th>
      <th>方向</th>
      <th>シングルパス (Mbps)</th>
      <th>マルチパス MinRTT (Mbps)</th>
      <th>マルチパス WLB (Mbps)</th>
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

## フェイルオーバー

<p class="section-desc">対称帯域 (150Mbps + 150Mbps)、非対称遅延 (10ms + 30ms RTT)。Path A → Path B の順に障害注入。</p>

<div v-if="failoverRows.length === 0">データがありません。</div>
<template v-else>
<div class="filter-bar">
  <label>スケジューラ:
    <select v-model="foSchedFilter">
      <option value="">すべて</option>
      <option value="wlb">WLB</option>
      <option value="minrtt">MinRTT</option>
    </select>
  </label>
  <label>障害パス:
    <select v-model="foPathFilter">
      <option value="">すべて</option>
      <option value="A">パス A</option>
      <option value="B">パス B</option>
    </select>
  </label>
</div>
<table>
  <thead>
    <tr>
      <th>コミット</th>
      <th>日付</th>
      <th>スケジューラ</th>
      <th>障害パス</th>
      <th>TTF (s)</th>
      <th>TTR (s)</th>
      <th>障害前 (Mbps)</th>
      <th>障害中 (Mbps)</th>
      <th>復旧 (Mbps)</th>
      <th>復旧後 (Mbps)</th>
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
      <td>{{ r.recovery }}</td>
      <td>{{ r.post }}</td>
    </tr>
  </tbody>
</table>
</template>

## 帯域集約

<p class="section-desc">Path A: 300Mbps/10ms, Path B: 80Mbps/30ms。理論値 380Mbps。</p>

<div v-if="aggregateRows.length === 0">データがありません。</div>
<template v-else>

<div class="filter-bar">
  <label>スケジューラ:
    <select v-model="aggSchedFilter">
      <option value="">すべて</option>
      <option value="wlb">WLB</option>
      <option value="minrtt">MinRTT</option>
    </select>
  </label>
  <label>ストリーム数:
    <select v-model="aggStreamsFilter">
      <option value="">すべて</option>
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
      <th>コミット</th>
      <th>日付</th>
      <th>スケジューラ</th>
      <th>ストリーム数</th>
      <th>シングルパス</th>
      <th>マルチパス</th>
      <th>ゲイン</th>
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

---
layout: page
---

<script setup>
import { ref, computed } from 'vue'
import { usePerfData } from '../../.vitepress/theme/composables/usePerfData'

const {
  loading, error,
  rawRows, failoverRows, aggregateRows,
  multipathSchedulerRows, udpSweepSummaryRows, udpSweepRows, ntnRows
} = usePerfData('/perf-data/weekly')

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

const udpSchedFilter = ref('wlb')
const filteredUdpSweepRows = computed(() => {
  return udpSweepRows.value.filter(r => {
    if (udpSchedFilter.value && r.scheduler !== udpSchedFilter.value) return false
    return true
  })
})
</script>

# 週次ベンチマーク

<p class="page-desc">毎週日曜日 3:00 UTC に実行される拡張ベンチマーク。<br>コミットごとのテストに加え、シナリオベースのテストを含みます。</p>

<ClientOnly>
<div v-if="loading">読み込み中...</div>
<div v-else-if="error && !error.includes('404')" style="color: red;">エラー: {{ error }}</div>
<div v-else-if="rawRows.length === 0 && multipathSchedulerRows.length === 0" class="no-data-block">
  週次データはまだありません。毎週日曜日 3:00 UTC に実行されます。
</div>
<template v-else>

## VPN スループット（エミュレーションなし、netns）

<div v-if="rawRows.length === 0">データなし。</div>
<table v-else>
  <thead>
    <tr><th>コミット</th><th>日付</th><th>方向</th><th>シングルパス (Mbps)</th><th>マルチパス MinRTT (Mbps)</th><th>マルチパス WLB (Mbps)</th></tr>
  </thead>
  <tbody>
    <tr v-for="(r, i) in rawRows" :key="'raw-' + i">
      <td><code>{{ r.commit }}</code></td><td>{{ r.date }}</td><td>{{ r.dir }}</td><td>{{ r.single }}</td><td>{{ r.minrtt }}</td><td>{{ r.wlb }}</td>
    </tr>
  </tbody>
</table>

## フェイルオーバー

<p class="section-desc">対称帯域 (150Mbps + 150Mbps)、非対称遅延 (10ms + 30ms RTT)。Path A → Path B の順に障害注入。</p>

<div v-if="failoverRows.length === 0">データなし。</div>
<template v-else>
<div class="filter-bar">
  <label>スケジューラ: <select v-model="foSchedFilter"><option value="">すべて</option><option value="wlb">WLB</option><option value="minrtt">MinRTT</option></select></label>
  <label>障害パス: <select v-model="foPathFilter"><option value="">すべて</option><option value="A">パス A</option><option value="B">パス B</option></select></label>
</div>
<table>
  <thead><tr><th>コミット</th><th>日付</th><th>スケジューラ</th><th>障害パス</th><th>TTF (s)</th><th>TTR (s)</th><th>障害前 (Mbps)</th><th>障害中 (Mbps)</th><th>復旧 (Mbps)</th><th>復旧後 (Mbps)</th></tr></thead>
  <tbody>
    <tr v-for="(r, i) in filteredFailoverRows" :key="'fo-' + i">
      <td><code>{{ r.commit }}</code></td><td>{{ r.date }}</td><td>{{ r.scheduler }}</td><td>{{ r.fault_path }}</td><td>{{ r.ttf }}</td><td>{{ r.ttr }}</td><td>{{ r.pre }}</td><td>{{ r.degraded }}</td><td>{{ r.recovery }}</td><td>{{ r.post }}</td>
    </tr>
  </tbody>
</table>
</template>

## 帯域集約

<div v-if="aggregateRows.length === 0">データなし。</div>
<template v-else>
<div class="filter-bar">
  <label>スケジューラ: <select v-model="aggSchedFilter"><option value="">すべて</option><option value="wlb">WLB</option><option value="minrtt">MinRTT</option></select></label>
  <label>ストリーム数: <select v-model="aggStreamsFilter"><option value="">すべて</option><option value="1">1</option><option value="4">4</option><option value="16">16</option><option value="64">64</option></select></label>
</div>
<table>
  <thead><tr><th>コミット</th><th>日付</th><th>スケジューラ</th><th>ストリーム数</th><th>シングルパス</th><th>マルチパス</th><th>ゲイン</th></tr></thead>
  <tbody>
    <tr v-for="(r, i) in filteredAggregateRows" :key="'agg-' + i">
      <td><code>{{ r.commit }}</code></td><td>{{ r.date }}</td><td>{{ r.scheduler }}</td><td>{{ r.streams }}</td><td>{{ r.single }} Mbps</td><td>{{ r.multi }} Mbps</td><td>{{ r.gain }}</td>
    </tr>
  </tbody>
</table>
</template>

## マルチパススケジューラシナリオ

<p class="section-desc">遅延・帯域・損失の異なる 8 つのネットワークシナリオで WLB と MinRTT スケジューラを比較。RTT = 片方向遅延 x 2。</p>

<details class="scenario-details">
<summary>シナリオ条件</summary>

- **equal_paths** — A: 50Mbps/10ms, B: 50Mbps/10ms
- **asymmetric_bandwidth** — A: 100Mbps/5ms, B: 50Mbps/20ms
- **high_jitter** — A: 50Mbps/10ms±5ms, B: 50Mbps/10ms±5ms
- **asymmetric_jitter** — A: 50Mbps/10ms（安定）, B: 50Mbps/10ms±8ms
- **lossy_path** — A: 50Mbps/10ms, B: 50Mbps/10ms/1% ロス
- **realistic_mixed** — A: 100Mbps/5ms, B: 50Mbps/20ms±5ms/0.5% ロス
- **mobile_dual_lte** — A: 50Mbps/30ms±10ms/0.5% ロス, B: 30Mbps/50ms±15ms/1% ロス
- **mobile_wifi_lte** — A: 80Mbps/5ms±2ms, B: 30Mbps/40ms±12ms/0.5% ロス

</details>

<div v-if="multipathSchedulerRows.length === 0">データなし。</div>
<table v-else>
  <thead>
    <tr><th>コミット</th><th>日付</th><th>シナリオ</th><th>シングル (Mbps)</th><th>WLB (Mbps)</th><th>MinRTT (Mbps)</th></tr>
  </thead>
  <tbody>
    <tr v-for="(r, i) in multipathSchedulerRows" :key="'ms-' + i">
      <td><code>{{ r.commit }}</code></td><td>{{ r.date }}</td><td>{{ r.scenario }}</td><td>{{ r.single }}</td><td>{{ r.wlb }}</td><td>{{ r.minrtt }}</td>
    </tr>
  </tbody>
</table>

## UDP レートスイープ

<p class="section-desc">Path A: 300Mbps/10ms, Path B: 80Mbps/30ms。UDP 送信レートを 200〜380 Mbps でスイープし、飽和点（ロス > 5%）を特定。ペイロード: 1100B、DL 方向。</p>

<div v-if="udpSweepSummaryRows.length === 0">データなし。</div>
<template v-else>

**飽和点**

<table>
  <thead><tr><th>コミット</th><th>日付</th><th>シングル (Mbps)</th><th>WLB (Mbps)</th><th>MinRTT (Mbps)</th></tr></thead>
  <tbody>
    <tr v-for="(r, i) in udpSweepSummaryRows" :key="'udps-' + i">
      <td><code>{{ r.commit }}</code></td><td>{{ r.date }}</td><td>{{ r.single_saturation }}</td><td>{{ r.wlb_saturation }}</td><td>{{ r.minrtt_saturation }}</td>
    </tr>
  </tbody>
</table>

**スイープ詳細**

<div class="filter-bar">
  <label>条件: <select v-model="udpSchedFilter"><option value="">すべて</option><option value="single">シングル</option><option value="wlb">WLB</option><option value="minrtt">MinRTT</option></select></label>
</div>
<table>
  <thead><tr><th>コミット</th><th>レート (Mbps)</th><th>スループット (Mbps)</th><th>ロス (%)</th><th>ジッタ (ms)</th></tr></thead>
  <tbody>
    <tr v-for="(r, i) in filteredUdpSweepRows" :key="'udpd-' + i">
      <td><code>{{ r.commit }}</code></td><td>{{ r.rate }}</td><td>{{ r.throughput }}</td><td>{{ r.loss }}</td><td>{{ r.jitter }}</td>
    </tr>
  </tbody>
</table>

</template>

## NTN 衛星

<p class="section-desc">3GPP NTN 仕様と Starlink 実測データに基づく衛星リンクプロファイルでのマルチパス性能テスト。RTT = 片方向遅延 x 2。</p>

<details class="scenario-details">
<summary>シナリオ条件</summary>

- **lte_leo_starlink** — A: LTE 50Mbps/15ms±3ms/0.2% ロス, B: LEO 100Mbps/25ms±8ms/0.5% ロス
- **lte_leo_high_orbit** — A: LTE 50Mbps/15ms±3ms/0.2% ロス, B: LEO 80Mbps/40ms±12ms/0.8% ロス
- **lte_geo** — A: LTE 50Mbps/15ms±3ms/0.2% ロス, B: GEO 20Mbps/300ms±5ms/0.2% ロス
- **wifi_leo** — A: WiFi 80Mbps/3ms±1ms, B: LEO 100Mbps/25ms±8ms/0.5% ロス
- **dual_leo** — A: LEO 100Mbps/25ms±8ms/0.5% ロス, B: LEO 80Mbps/35ms±10ms/0.8% ロス

</details>

<div v-if="ntnRows.length === 0">データなし。</div>
<table v-else>
  <thead>
    <tr><th>コミット</th><th>日付</th><th>シナリオ</th><th>シングル (Mbps)</th><th>WLB (Mbps)</th><th>MinRTT (Mbps)</th></tr>
  </thead>
  <tbody>
    <tr v-for="(r, i) in ntnRows" :key="'ntn-' + i">
      <td><code>{{ r.commit }}</code></td><td>{{ r.date }}</td><td>{{ r.scenario }}</td><td>{{ r.single }}</td><td>{{ r.wlb }}</td><td>{{ r.minrtt }}</td>
    </tr>
  </tbody>
</table>

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

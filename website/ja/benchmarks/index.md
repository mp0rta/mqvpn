---
layout: doc
---

<script setup>
import { computed } from 'vue'
import { usePerfData } from '../../.vitepress/theme/composables/usePerfData'

const push = usePerfData('/perf-data', 1)

const latestRaw = computed(() => push.rawRows.value[0] || null)
const latestFailover = computed(() => push.failoverRows.value.find(r => r.fault_path === 'A') || null)
const latestAggregate = computed(() => {
  const rows = push.aggregateRows.value
  if (!rows.length) return null
  return rows.reduce((a, b) => parseFloat(a.gain) > parseFloat(b.gain) ? a : b)
})

</script>

# ベンチマーク

<p class="page-desc">CI による自動ベンチマーク結果です。<br>環境: Proxmox VM, i9-13900H, 4 vCPU（ピニング）, Ubuntu 24.04</p>

## コミットごとの結果

<p class="section-desc">main へのプッシュごとに実行されるベンチマーク。</p>

<ClientOnly>
<div v-if="push.loading.value">読み込み中...</div>
<div v-else-if="push.error.value" style="color: red;">{{ push.error.value }}</div>
<template v-else>

<div class="summary-grid">
  <div class="summary-card">
    <h3>VPN スループット</h3>
    <div v-if="latestRaw">
      <div class="stat">{{ latestRaw.wlb }} <span class="unit">Mbps</span></div>
      <div class="label">WLB ({{ latestRaw.dir }})</div>
      <div class="meta"><code>{{ latestRaw.commit }}</code> &middot; {{ latestRaw.date }}</div>
    </div>
    <div v-else class="no-data">データがありません</div>
  </div>

  <div class="summary-card">
    <h3>フェイルオーバー TTF</h3>
    <div v-if="latestFailover">
      <div class="stat">{{ latestFailover.ttf }}<span class="unit">s</span></div>
      <div class="label">WLB フォールバック時間</div>
      <div class="meta"><code>{{ latestFailover.commit }}</code> &middot; {{ latestFailover.date }}</div>
    </div>
    <div v-else class="no-data">データがありません</div>
  </div>

  <div class="summary-card">
    <h3>帯域集約</h3>
    <div v-if="latestAggregate">
      <div class="stat">{{ latestAggregate.multi }} <span class="unit">Mbps</span></div>
      <div class="label">{{ latestAggregate.scheduler.toUpperCase() }}, {{ latestAggregate.streams }} ストリーム &mdash; <strong>+{{ latestAggregate.gain }}</strong> vs シングルパス</div>
      <div class="label">回線: 300Mbps + 80Mbps（理論値 380Mbps）</div>
      <div class="meta"><code>{{ latestAggregate.commit }}</code> &middot; {{ latestAggregate.date }}</div>
    </div>
    <div v-else class="no-data">データがありません</div>
  </div>
</div>

<p><a href="/ja/benchmarks/per-commit">すべて表示 &rarr;</a></p>

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

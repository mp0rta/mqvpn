---
layout: doc
---

<script setup>
import { computed } from 'vue'
import { usePerfData } from '../../.vitepress/theme/composables/usePerfData'

const push = usePerfData('', 1)

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

## ハイブリッド TCP レーン集約（v0.9.0）

<p class="section-desc">対称 2×100 Mbit / 25 ms、TCP 上り、<code>iperf3 -P {1,2,4,8,16}</code>、3 回。</p>

ハイブリッドの TCP **ストリームレーン**はクライアント側で TCP を終端し、順序保証つきの QUIC STREAM で中継します。そのため単一フローでも両パスを集約でき、全ストリーム数で **~187 Mbps**（200 Mbps 集約上限の約 93 %）に到達します。一方、生のマルチパス（データグラムトンネリング）は単一フローがパス間の並べ替えでバックオフするため、並列ストリームが増えて初めて追いつきます（WLB <code>-P 1</code>：96 → 187 Mbps、**+95 %**）。

![ハイブリッド TCP レーン — MinRTT スケジューラ](/img/bench-hybrid-minrtt.png)

![ハイブリッド TCP レーン — WLB スケジューラ](/img/bench-hybrid-wlb.png)

**非対称パス** — 同じベンチを非対称 A = 300 Mbit / 10 ms + B = 80 Mbit / 30 ms（集約 380 Mbps）で実施。ハイブリッド ON は非対称パスでも集約を飽和させ、<code>-P ≥ 2</code> で **350–357 Mbps**（380 Mbps の約 93 %）に到達します。一方、生のマルチパスはここでは追いつききれません。WLB はパス間の並べ替えペナルティ（RTT 20 ms と 60 ms の差）により 16 ストリームでも 330 Mbps で頭打ちになり、MinRTT は cwnd が詰まったときしか遅い側へあふれない設計のため、ほぼ高速パス単独（~275 Mbps）に留まります。そのため対称構成と異なり、レーンの利得は全ストリーム数で持続します：MinRTT **+29–35 %**、WLB **+26 %**（<code>-P 1</code>）→ **+7 %**（<code>-P 16</code>）。

![ハイブリッド TCP レーン（非対称パス）— MinRTT スケジューラ](/img/bench-hybrid-asym-minrtt.png)

![ハイブリッド TCP レーン（非対称パス）— WLB スケジューラ](/img/bench-hybrid-asym-wlb.png)

## SRT ライブ配信

<p class="section-desc">エミュレートした劣悪回線（netns）上の SRT 伝送。mqvpn はデフォルト設定（WLB スケジューラ、BBR v2）+ SRT 受信側 <code>lossmaxttl=32</code>。</p>

弱い回線・ロスの多い回線でも、2 本束ねることで視聴に耐えない SRT 配信が安定します。以下は各アップリンクが 6 Mbit しか出ない環境に 8 Mbps の FHD 配信を流した比較 — 単一回線（左）と、同じ 2 回線を mqvpn で束ねた場合（右）：

<video controls muted playsinline style="width: 100%; border-radius: 8px;" src="https://github.com/user-attachments/assets/9862b717-a00f-4faf-a098-0e10d912b8a5"></video>

| シナリオ | 単一回線（direct） | mqvpn（2 パス） |
|---|---|---|
| 帯域不足（8 Mbps FHD を 2 × 6 Mbit で） | VMAF 8.6、フリーズ 1.2 秒 | VMAF **87.7**、フリーズ 0 秒 |
| 単一回線では収まらないレート（120 Mbps を 2 × 100 Mbit で） | ストリームロス 31.5 % | ストリームロス **0.06 %** |
| デュアルセルラー（40 + 30 Mbit のロスあり回線に 42 Mbps） | ストリームロス 20–40 % | ストリームロス **0.9 %** |

<p class="section-desc">VMAF：体感画質スコア（0–100、高いほど良い）。</p>

フルレポートと比較動画: [`bench_results/srt/`](https://github.com/mp0rta/mqvpn/tree/main/bench_results/srt)

## RTMP ライブ配信

<p class="section-desc">エミュレートした劣悪回線（netns）上の RTMP 配信。mqvpn のハイブリッド TCP レーン経由。配信ソフトは OBS 相当の挙動（10 秒で切断検知、2 秒間隔で再接続）。</p>

RTMP は単一の TCP 接続で送るプロトコルで、それ自体では回線を束ねられません。mqvpn を通すと、配信ソフトも配信先も無改造のまま透過的にボンディングされます。以下は配信中に 2 本のうち 1 本を 30 秒間遮断した比較 — 単一回線（左）は約 33 秒停止し、mqvpn（右）は止まりません：

<video controls muted playsinline style="width: 100%; border-radius: 8px;" src="https://github.com/user-attachments/assets/04d3b4f9-be82-4a85-857d-474e503bfa94"></video>

| シナリオ | 単一回線（direct） | mqvpn（2 パス） |
|---|---|---|
| 帯域不足（8 Mbps を 2 × 6 Mbit で） | 5.7 Mbps 止まり、ライブから遅れ続ける | **7.8 Mbps、遅れなし** |
| バースト損失（モバイル回線相当） | 切断を繰り返し、ほぼ届かない | **安定、切断なし** |
| 片方の回線を 30 秒遮断 | 配信も切断、回線復旧まで停止 | **配信は切れない** |

数値の詳細はフルレポート: [RTMP ボンディング測定レポート（英語）](https://github.com/mp0rta/mqvpn/blob/main/docs/report/2026-08-11-rtmp-direct-vs-mqvpn-bonding-en.md) — データと動画: [`bench_results/rtmp/`](https://github.com/mp0rta/mqvpn/tree/main/bench_results/rtmp)

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

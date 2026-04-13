import { ref, onMounted, computed, type Ref } from 'vue'

// ── Format helpers ──

export function fmtDate(ts: string) {
  return new Date(ts).toISOString().slice(0, 10)
}

export function fmtCommit(c: string) {
  return c ? c.slice(0, 7) : '?'
}

export function fmtNum(v: number | null | undefined, digits = 1) {
  if (v == null) return '-'
  return Number(v).toFixed(digits)
}

// ── Data types ──

export interface IndexEntry {
  commit: string
  timestamp: string
  type: string
  files: string[]
}

export interface BenchmarkItem {
  commit: string
  timestamp: string
  data: any
}

// ── Fetch helpers ──

async function fetchJson(url: string) {
  const res = await fetch(url)
  if (!res.ok) throw new Error(`${url}: ${res.status}`)
  return res.json()
}

/**
 * Fetch benchmark data from a perf-data directory.
 * @param basePath - e.g. '/perf-data' or '/perf-data/weekly'
 * @param maxEntries - how many index entries to load (default 10)
 */
export function usePerfData(basePath: string, maxEntries = 10) {
  const loading = ref(true)
  const error = ref('')
  const items: Ref<BenchmarkItem[]> = ref([])

  onMounted(async () => {
    try {
      const index: IndexEntry[] = await fetchJson(`${basePath}/index.json`)
      const entries = index.slice(0, maxEntries)

      const result: BenchmarkItem[] = []
      for (const entry of entries) {
        for (const file of entry.files || []) {
          const data = await fetchJson(`${basePath}/${file}`)
          result.push({
            commit: entry.commit,
            timestamp: entry.timestamp,
            data,
          })
        }
      }
      items.value = result
    } catch (e: any) {
      error.value = e.message || 'Failed to load benchmark data.'
    } finally {
      loading.value = false
    }
  })

  // ── Computed row extractors ──

  const rawRows = computed(() => {
    const rows: any[] = []
    for (const item of items.value) {
      if (item.data.test !== 'raw_throughput') continue
      for (const dir of Object.keys(item.data.results || {})) {
        const r = item.data.results[dir]
        rows.push({
          commit: fmtCommit(item.commit),
          date: fmtDate(item.timestamp),
          dir,
          single: fmtNum(r.single_path_mbps),
          minrtt: fmtNum(r.multipath_minrtt_mbps),
          wlb: fmtNum(r.multipath_wlb_mbps),
        })
      }
    }
    return rows
  })

  const failoverRows = computed(() => {
    const rows: any[] = []
    for (const item of items.value) {
      if (item.data.test !== 'failover') continue
      const w = item.data.results?.wlb || {}
      const m = item.data.results?.minrtt || {}
      rows.push({
        commit: fmtCommit(item.commit),
        date: fmtDate(item.timestamp),
        wlb_ttr: fmtNum(w.ttr_sec, 2),
        minrtt_ttr: fmtNum(m.ttr_sec, 2),
        wlb_pre: fmtNum(w.pre_fault_avg_mbps),
        wlb_degraded: fmtNum(w.degraded_avg_mbps),
        wlb_post: fmtNum(w.post_recover_avg_mbps),
        minrtt_pre: fmtNum(m.pre_fault_avg_mbps),
        minrtt_degraded: fmtNum(m.degraded_avg_mbps),
        minrtt_post: fmtNum(m.post_recover_avg_mbps),
      })
    }
    return rows
  })

  const aggregateRows = computed(() => {
    const rows: any[] = []
    for (const item of items.value) {
      if (item.data.test !== 'aggregate') continue
      for (const sched of Object.keys(item.data.results || {})) {
        const arr = item.data.results[sched]
        if (!Array.isArray(arr)) continue
        for (const r of arr) {
          rows.push({
            commit: fmtCommit(item.commit),
            date: fmtDate(item.timestamp),
            scheduler: sched,
            streams: r.streams,
            single: fmtNum(r.single_path_mbps),
            multi: fmtNum(r.multipath_mbps),
            gain: fmtNum(r.gain_pct) + '%',
          })
        }
      }
    }
    return rows
  })

  // ── Weekly-only extractors ──

  const multipathSchedulerRows = computed(() => {
    const rows: any[] = []
    for (const item of items.value) {
      if (item.data.test !== 'multipath_scheduler') continue
      for (const s of item.data.scenarios || []) {
        rows.push({
          commit: fmtCommit(item.commit),
          date: fmtDate(item.timestamp),
          scenario: s.name,
          netem_a: s.netem_a,
          netem_b: s.netem_b,
          single: fmtNum(s.single_mbps),
          wlb: fmtNum(s.wlb_mbps),
          minrtt: fmtNum(s.minrtt_mbps),
        })
      }
    }
    return rows
  })

  const flowScalingRows = computed(() => {
    const rows: any[] = []
    for (const item of items.value) {
      if (item.data.test !== 'flow_scaling') continue
      for (const sched of Object.keys(item.data.results || {})) {
        const arr = item.data.results[sched]
        if (!Array.isArray(arr)) continue
        for (const r of arr) {
          rows.push({
            commit: fmtCommit(item.commit),
            date: fmtDate(item.timestamp),
            scheduler: sched,
            streams: r.streams,
            mbps: fmtNum(r.mbps),
          })
        }
      }
    }
    return rows
  })

  const udpSchedulerRows = computed(() => {
    const rows: any[] = []
    for (const item of items.value) {
      if (item.data.test !== 'udp_scheduler') continue
      for (const s of item.data.scenarios || []) {
        for (const sched of ['wlb', 'minrtt']) {
          const d = s[sched] || {}
          rows.push({
            commit: fmtCommit(item.commit),
            date: fmtDate(item.timestamp),
            scenario: s.name,
            scheduler: sched,
            mbps: fmtNum(d.mbps),
            jitter: fmtNum(d.jitter_ms, 2),
            lost: fmtNum(d.lost_pct, 2) + '%',
          })
        }
      }
    }
    return rows
  })

  const ntnRows = computed(() => {
    const rows: any[] = []
    for (const item of items.value) {
      if (item.data.test !== 'ntn') continue
      for (const s of item.data.scenarios || []) {
        rows.push({
          commit: fmtCommit(item.commit),
          date: fmtDate(item.timestamp),
          scenario: s.name || s.description,
          single: fmtNum(s.single_mbps),
          wlb: fmtNum(s.wlb_mbps),
          minrtt: fmtNum(s.minrtt_mbps),
        })
      }
    }
    return rows
  })

  return {
    loading,
    error,
    items,
    rawRows,
    failoverRows,
    aggregateRows,
    multipathSchedulerRows,
    flowScalingRows,
    udpSchedulerRows,
    ntnRows,
  }
}

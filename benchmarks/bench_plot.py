#!/usr/bin/env python3
"""bench_plot.py — Generate PNG plots from benchmark JSON.

Auto-detects test type from the JSON 'test' field:
  - "failover"  → time-series throughput with fault/recovery markers
  - "aggregate" → grouped bar chart (single-path vs multipath)
  - "udp_sweep" → throughput-loss and jitter curves vs send rate

For raw iperf3 JSON (no 'test' field), treats as failover-style time-series.

Usage:
  python3 bench_plot.py <json-file> [<json-file> ...]
  python3 bench_plot.py bench_results/failover_netns_*.json
  python3 bench_plot.py bench_results/udp_sweep_netns_*.json
  python3 bench_plot.py benchmarks/m3_ec2/m3_failover.json
"""

import json
import sys
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


DOCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'docs')
COLOR_MAIN = '#0077cc'
COLOR_GRAY = '#666666'
COLOR_RED = '#cc0000'
COLOR_ORANGE = '#e67300'
DPI = 150
FIGSIZE = (10, 6)


def plot_failover(data, output_path):
    """Plot failover time-series with fault/recovery markers."""
    plt.style.use('default')
    fig, ax = plt.subplots(figsize=FIGSIZE, facecolor='white')
    ax.set_facecolor('white')

    intervals = data['intervals']
    times = [iv['time_sec'] for iv in intervals]
    mbps = [iv['mbps'] for iv in intervals]

    fault_inject = data['fault_inject_sec']
    fault_recover = data['fault_recover_sec']
    pre_fault_avg = data.get('pre_fault_avg_mbps', 0)

    # --- Compute failover & recovery metrics ---
    # Failover: check for zero-throughput intervals after fault inject
    zero_intervals = [iv for iv in intervals
                      if iv['time_sec'] > fault_inject
                      and iv['time_sec'] <= fault_recover
                      and iv['mbps'] == 0.0]
    has_outage = len(zero_intervals) > 0

    # Recovery time: from fault_recover to 90% of pre-fault avg
    recovery_time = None
    if pre_fault_avg > 0:
        threshold = pre_fault_avg * 0.9
        for iv in intervals:
            if iv['time_sec'] > fault_recover and iv['mbps'] >= threshold:
                recovery_time = round(iv['time_sec'] - fault_recover, 1)
                break

    # Throughput line
    ax.plot(times, mbps, color=COLOR_MAIN, linewidth=1.2, alpha=0.9,
            label=f'Throughput (pre-fault avg: {pre_fault_avg:.0f} Mbps)')

    # Fault injection / recovery vertical lines
    ax.axvline(x=fault_inject, color=COLOR_RED, linestyle='--', linewidth=1.5,
               alpha=0.8, label=f'Path A down (t={fault_inject}s)')
    ax.axvline(x=fault_recover, color=COLOR_RED, linestyle=':', linewidth=1.5,
               alpha=0.8, label=f'Path A restored (t={fault_recover}s)')

    # Degraded band (path A down, traffic on path B only)
    ax.axvspan(fault_inject, fault_recover, alpha=0.08, color=COLOR_ORANGE,
               label='Degraded (single path)')

    # Recovery band (path restored → full throughput)
    if recovery_time is not None:
        recovery_end = fault_recover + recovery_time
        ax.axvspan(fault_recover, recovery_end, alpha=0.10, color='#22aa44',
                   label=f'Recovery: {recovery_time:.0f}s')

    # Failover annotation
    if has_outage:
        failover_label = f'Failover: outage ({len(zero_intervals)} intervals at 0)'
    else:
        failover_label = 'Failover: 0 downtime'
    ax.plot([], [], ' ', label=failover_label)

    ax.set_xlabel('Time (seconds)', fontsize=12, color='black')
    ax.set_ylabel('Throughput (Mbps)', fontsize=12, color='black')
    ax.set_title(f'Failover & Recovery — {data.get("env", "unknown")}',
                 fontsize=14, color='black')
    ax.tick_params(colors='black')
    ax.legend(loc='lower left', fontsize=9, framealpha=0.7)
    ax.grid(True, alpha=0.2, color='gray')
    ax.set_xlim(0, max(times) if times else 60)
    ax.set_ylim(bottom=0)

    fig.tight_layout()
    fig.savefig(output_path, dpi=DPI, facecolor='white')
    plt.close(fig)
    print(f'  Saved: {output_path}')


def plot_failover_raw_iperf3(data, output_path):
    """Plot raw iperf3 JSON as failover time-series (for m3_failover.json)."""
    intervals = []
    for iv in data.get('intervals', []):
        s = iv['sum']
        intervals.append({
            'time_sec': round(s['end'], 1),
            'mbps': round(s['bits_per_second'] / 1e6, 1)
        })

    # Default fault times for M3 benchmark (20s inject, 40s recover)
    synth = {
        'test': 'failover',
        'env': 'ec2',
        'intervals': intervals,
        'fault_inject_sec': 20,
        'fault_recover_sec': 40,
        'pre_fault_avg_mbps': 0,
        'ttr_sec': None,
    }

    # Calculate pre-fault average
    pre = [iv['mbps'] for iv in intervals if iv['time_sec'] <= 20]
    synth['pre_fault_avg_mbps'] = sum(pre) / len(pre) if pre else 0

    # Calculate TTR
    threshold = synth['pre_fault_avg_mbps'] * 0.9
    for iv in intervals:
        if iv['time_sec'] > 20 and iv['mbps'] >= threshold:
            synth['ttr_sec'] = round(iv['time_sec'] - 20, 2)
            break

    plot_failover(synth, output_path)


def plot_aggregate(data, output_path):
    """Plot aggregate bandwidth as grouped bar chart."""
    plt.style.use('default')
    fig, ax = plt.subplots(figsize=FIGSIZE, facecolor='white')
    ax.set_facecolor('white')

    results = data['results']
    streams = [r['streams'] for r in results]
    single = [r['single_path_mbps'] for r in results]
    multi = [r['multipath_mbps'] for r in results]
    theoretical_max = data.get('theoretical_max_mbps', 0)

    x_pos = range(len(streams))
    bar_width = 0.35

    bars_single = ax.bar([p - bar_width / 2 for p in x_pos], single,
                         bar_width, label='Single-path', color=COLOR_GRAY,
                         alpha=0.85)
    bars_multi = ax.bar([p + bar_width / 2 for p in x_pos], multi,
                        bar_width, label='Multipath', color=COLOR_MAIN,
                        alpha=0.85)

    # Theoretical max line
    if theoretical_max > 0:
        ax.axhline(y=theoretical_max, color=COLOR_RED, linestyle='--',
                   linewidth=1.5, alpha=0.7,
                   label=f'Theoretical max ({theoretical_max} Mbps)')

    # Value labels on bars
    for bar in bars_single:
        height = bar.get_height()
        if height > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, height + 2,
                    f'{height:.0f}', ha='center', va='bottom',
                    fontsize=8, color='black')

    for bar in bars_multi:
        height = bar.get_height()
        if height > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, height + 2,
                    f'{height:.0f}', ha='center', va='bottom',
                    fontsize=8, color='black')

    ax.set_xlabel('iperf3 Parallel Streams (-P)', fontsize=12, color='black')
    ax.set_ylabel('Throughput (Mbps)', fontsize=12, color='black')
    ax.set_title(f'Bandwidth Aggregation — {data.get("env", "unknown")}', fontsize=14, color='black')
    ax.set_xticks(list(x_pos))
    ax.set_xticklabels([str(s) for s in streams])
    ax.tick_params(colors='black')
    ax.legend(fontsize=10, framealpha=0.7)
    ax.grid(True, alpha=0.2, color='gray', axis='y')
    ax.set_ylim(bottom=0)

    fig.tight_layout()
    fig.savefig(output_path, dpi=DPI, facecolor='white')
    plt.close(fig)
    print(f'  Saved: {output_path}')


def plot_aggregate_compare(datasets, output_path):
    """Plot comparison of multiple aggregate results (e.g. WLB vs MinRTT)."""
    plt.style.use('default')
    fig, ax = plt.subplots(figsize=FIGSIZE, facecolor='white')
    ax.set_facecolor('white')

    # Use last dataset for single-path baseline (stable reference)
    base = datasets[0]
    streams = [r['streams'] for r in base['results']]
    x_pos = list(range(len(streams)))
    n_datasets = len(datasets)
    bar_width = 0.8 / (n_datasets + 1)

    # Bar order: single-path, then each dataset's multipath (reversed input order)
    multipath_colors = ['#e67300', '#0077cc', '#22aa44', '#cc0000']

    # Single-path baseline (from last dataset)
    single = [r['single_path_mbps'] for r in datasets[-1]['results']]
    offset = -(n_datasets) / 2 * bar_width
    bars_s = ax.bar([p + offset for p in x_pos], single, bar_width,
                    label='Single-path', color=COLOR_GRAY, alpha=0.7)
    for bar in bars_s:
        height = bar.get_height()
        if height > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, height + 2,
                    f'{height:.0f}', ha='center', va='bottom',
                    fontsize=7, color='black')

    # Each dataset's multipath results (reversed so first arg appears rightmost)
    for i, data in enumerate(reversed(datasets)):
        sched = data.get('scheduler', f'run{i+1}')
        multi = [r['multipath_mbps'] for r in data['results']]
        offset = (-(n_datasets) / 2 + (i + 1)) * bar_width
        color = multipath_colors[i % len(multipath_colors)]
        bars = ax.bar([p + offset for p in x_pos], multi, bar_width,
                      label=f'Multipath ({sched})', color=color, alpha=0.85)
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, height + 2,
                        f'{height:.0f}', ha='center', va='bottom',
                        fontsize=7, color='black')

    # Theoretical max
    theoretical_max = base.get('theoretical_max_mbps', 0)
    if theoretical_max > 0:
        ax.axhline(y=theoretical_max, color=COLOR_RED, linestyle='--',
                   linewidth=1.5, alpha=0.7,
                   label=f'Theoretical max ({theoretical_max} Mbps)')

    env = base.get('env', 'unknown')
    sched_names = [d.get('scheduler', '?') for d in reversed(datasets)]
    ax.set_xlabel('iperf3 Parallel Streams (-P)', fontsize=12, color='black')
    ax.set_ylabel('Throughput (Mbps)', fontsize=12, color='black')
    ax.set_title(f'Bandwidth Aggregation — {" vs ".join(sched_names)} ({env})',
                 fontsize=14, color='black')
    ax.set_xticks(x_pos)
    ax.set_xticklabels([str(s) for s in streams])
    ax.tick_params(colors='black')
    ax.legend(fontsize=8, framealpha=0.7, loc='upper left')
    ax.grid(True, alpha=0.2, color='gray', axis='y')
    ax.set_ylim(bottom=0)

    fig.tight_layout()
    fig.savefig(output_path, dpi=DPI, facecolor='white')
    plt.close(fig)
    print(f'  Saved: {output_path}')


CONDITION_COLORS = {
    'single_path': COLOR_GRAY,
    'multipath:wlb': COLOR_MAIN,
    'multipath:minrtt': COLOR_ORANGE,
    'multipath_lossy:wlb': COLOR_RED,
}

CONDITION_LABELS = {
    'single_path:wlb': 'Single-path',
    'multipath:wlb': 'Multipath (WLB)',
    'multipath:minrtt': 'Multipath (MinRTT)',
    'multipath_lossy:wlb': 'Multipath (WLB, lossy)',
}


def plot_udp_sweep_loss(sweeps, pkt_size, env, theoretical_max, output_path):
    """Plot loss rate vs send rate for a given packet size."""
    plt.style.use('default')
    fig, ax = plt.subplots(figsize=FIGSIZE, facecolor='white')
    ax.set_facecolor('white')

    for sw in sweeps:
        if sw['packet_size'] != pkt_size:
            continue

        key = f"{sw['condition']}:{sw['scheduler']}"
        color = CONDITION_COLORS.get(key,
                    CONDITION_COLORS.get(sw['condition'], COLOR_GRAY))
        label = CONDITION_LABELS.get(key, key)

        rates = [r['target_mbps'] for r in sw['results']]
        losses = [r['lost_percent'] for r in sw['results']]

        ax.plot(rates, losses, color=color, linewidth=1.5, alpha=0.9,
                marker='o', markersize=4, label=label)

    if theoretical_max > 0:
        ax.axvline(x=theoretical_max, color=COLOR_RED, linestyle=':',
                   linewidth=1, alpha=0.5,
                   label=f'Theoretical max ({theoretical_max} Mbps)')

    ax.set_xlabel('Target Send Rate (Mbps)', fontsize=12, color='black')
    ax.set_ylabel('Loss (%)', fontsize=12, color='black')
    ax.set_title(
        f'UDP Loss — {pkt_size}B packets ({env})', fontsize=14, color='black')
    ax.tick_params(colors='black')
    ax.legend(fontsize=9, framealpha=0.7)
    ax.grid(True, alpha=0.2, color='gray')
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)

    fig.tight_layout()
    fig.savefig(output_path, dpi=DPI, facecolor='white')
    plt.close(fig)
    print(f'  Saved: {output_path}')


def plot_udp_sweep_jitter(sweeps, pkt_size, env, theoretical_max, output_path):
    """Plot jitter vs send rate for a given packet size."""
    plt.style.use('default')
    fig, ax = plt.subplots(figsize=FIGSIZE, facecolor='white')
    ax.set_facecolor('white')

    for sw in sweeps:
        if sw['packet_size'] != pkt_size:
            continue

        key = f"{sw['condition']}:{sw['scheduler']}"
        color = CONDITION_COLORS.get(key,
                    CONDITION_COLORS.get(sw['condition'], COLOR_GRAY))
        label = CONDITION_LABELS.get(key, key)

        rates = [r['target_mbps'] for r in sw['results']]
        jitters = [r['jitter_ms'] for r in sw['results']]

        ax.plot(rates, jitters, color=color, linewidth=1.5, alpha=0.9,
                marker='o', markersize=4, label=label)

    if theoretical_max > 0:
        ax.axvline(x=theoretical_max, color=COLOR_RED, linestyle=':',
                   linewidth=1, alpha=0.5,
                   label=f'Theoretical max ({theoretical_max} Mbps)')

    ax.set_xlabel('Target Send Rate (Mbps)', fontsize=12, color='black')
    ax.set_ylabel('Jitter (ms)', fontsize=12, color='black')
    ax.set_title(
        f'UDP Jitter — {pkt_size}B packets ({env})', fontsize=14, color='black')
    ax.tick_params(colors='black')
    ax.legend(fontsize=9, framealpha=0.7)
    ax.grid(True, alpha=0.2, color='gray')
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)

    fig.tight_layout()
    fig.savefig(output_path, dpi=DPI, facecolor='white')
    plt.close(fig)
    print(f'  Saved: {output_path}')


def process_file(filepath):
    """Process a single JSON file and generate the appropriate plot."""
    with open(filepath) as f:
        data = json.load(f)

    os.makedirs(DOCS_DIR, exist_ok=True)

    test_type = data.get('test')

    if test_type == 'failover':
        env = data.get('env', 'unknown')
        fault_path = data.get('fault_path', '')
        suffix = f'_path{fault_path}' if fault_path else ''
        output_path = os.path.join(DOCS_DIR, f'failover_{env}{suffix}.png')
        plot_failover(data, output_path)

    elif test_type == 'aggregate':
        env = data.get('env', 'unknown')
        output_path = os.path.join(DOCS_DIR, f'aggregate_{env}.png')
        plot_aggregate(data, output_path)

    elif test_type == 'udp_sweep':
        env = data.get('env', 'unknown')
        sweeps = data.get('sweeps', [])
        pkt_sizes = sorted({s['packet_size'] for s in sweeps})
        theoretical_max = data.get('theoretical_max_mbps', 0)

        for pkt in pkt_sizes:
            # Only show theoretical max line for bulk packet sizes
            tmax = theoretical_max if pkt >= 1000 else 0

            loss_path = os.path.join(
                DOCS_DIR, f'udp_sweep_{env}_{pkt}B_loss.png')
            plot_udp_sweep_loss(sweeps, pkt, env, tmax, loss_path)

            jitter_path = os.path.join(
                DOCS_DIR, f'udp_sweep_{env}_{pkt}B_jitter.png')
            plot_udp_sweep_jitter(sweeps, pkt, env, tmax, jitter_path)

    elif 'intervals' in data and isinstance(data['intervals'], list):
        # Raw iperf3 JSON (e.g. m3_failover.json)
        basename = os.path.splitext(os.path.basename(filepath))[0]
        output_path = os.path.join(DOCS_DIR, f'{basename}.png')
        plot_failover_raw_iperf3(data, output_path)

    else:
        print(f'  Skip: {filepath} (unknown format)')


def main():
    if len(sys.argv) < 2:
        print('Usage: bench_plot.py <json-file> [<json-file> ...]')
        sys.exit(1)

    files = sys.argv[1:]

    # If multiple files of the same test type, generate comparison plot
    if len(files) >= 2:
        datasets = []
        for fp in files:
            with open(fp) as f:
                datasets.append(json.load(f))

        test_types = {d.get('test') for d in datasets}
        if len(test_types) == 1 and 'aggregate' in test_types:
            os.makedirs(DOCS_DIR, exist_ok=True)
            env = datasets[0].get('env', 'unknown')
            sched_names = [d.get('scheduler', 'unknown') for d in reversed(datasets)]
            output_path = os.path.join(DOCS_DIR,
                f'aggregate_compare_{"_vs_".join(sched_names)}_{env}.png')
            print(f'Comparing: {" vs ".join(sched_names)}')
            plot_aggregate_compare(datasets, output_path)
            return

    for filepath in files:
        print(f'Processing: {filepath}')
        process_file(filepath)


if __name__ == '__main__':
    main()

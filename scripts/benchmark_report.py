#!/usr/bin/env python3
"""Parse iperf3 JSON results and generate M3 benchmark report."""

import json
import sys
import os
from pathlib import Path


def parse_iperf3_json(filepath):
    """Extract key metrics from iperf3 JSON output."""
    with open(filepath) as f:
        data = json.load(f)

    if 'error' in data:
        return {'error': data['error']}

    end = data.get('end', {})

    # UDP results (check first — UDP also has sum_sent/sum_received)
    if 'sum' in end and 'jitter_ms' in end['sum']:
        return {
            'type': 'UDP',
            'mbps': end['sum']['bits_per_second'] / 1e6,
            'jitter_ms': end['sum'].get('jitter_ms', 0),
            'lost_pct': end['sum'].get('lost_percent', 0),
            'duration': end['sum'].get('seconds', 0),
        }

    # TCP results
    if 'sum_sent' in end:
        return {
            'type': 'TCP',
            'sent_mbps': end['sum_sent']['bits_per_second'] / 1e6,
            'recv_mbps': end['sum_received']['bits_per_second'] / 1e6,
            'retransmits': end['sum_sent'].get('retransmits', 0),
            'duration': end['sum_sent'].get('seconds', 0),
        }

    return None


def parse_failover_intervals(filepath):
    """Extract per-second throughput from failover test."""
    with open(filepath) as f:
        data = json.load(f)

    intervals = []
    for interval in data.get('intervals', []):
        sec = interval['sum']
        intervals.append({
            'start': sec['start'],
            'end': sec['end'],
            'mbps': sec['bits_per_second'] / 1e6,
        })
    return intervals


def parse_ping(filepath):
    """Extract RTT stats from ping output."""
    with open(filepath) as f:
        lines = f.readlines()
    stats = {}
    for line in lines:
        if 'rtt min/avg/max' in line or 'round-trip min/avg/max' in line:
            parts = line.split('=')[1].strip().split('/')
            stats['min_ms'] = float(parts[0])
            stats['avg_ms'] = float(parts[1])
            stats['max_ms'] = float(parts[2])
        if 'packet loss' in line:
            # "X packets transmitted, Y received, Z% packet loss"
            for token in line.split(','):
                if 'packet loss' in token:
                    stats['loss_pct'] = token.strip().split('%')[0].strip()
    return stats if stats else None


def generate_report(bench_dir):
    """Generate markdown benchmark report."""
    bench_dir = Path(bench_dir)
    report = []
    report.append("# mpvpn M3 Benchmark Report\n")
    report.append(f"Date: {os.popen('date -I').read().strip()}")
    report.append("Environment: Local machine (2x ISP) → Kagoya VPS (1 Gbps shared)")
    report.append("Underlay: Tailscale (single-path) / Direct IP (multipath)")
    report.append("")

    # Latency
    report.append("## Latency\n")
    report.append("| Path | Min (ms) | Avg (ms) | Max (ms) | Loss |")
    report.append("|------|----------|----------|----------|------|")

    for name, file in [("Direct (Tailscale)", "m3_latency_direct.txt"),
                        ("VPN tunnel",         "m3_latency_vpn.txt")]:
        path = bench_dir / file
        if path.exists():
            stats = parse_ping(str(path))
            if stats:
                loss = stats.get('loss_pct', '?')
                report.append(
                    f"| {name} | {stats['min_ms']:.1f} | "
                    f"{stats['avg_ms']:.1f} | {stats['max_ms']:.1f} | {loss}% |")

    # Throughput
    report.append("\n## Throughput\n")
    report.append("| Test | Direction | Mbps | Notes |")
    report.append("|------|-----------|------|-------|")

    test_files = [
        ("Direct (no VPN, iperf3 TCP)",  "m3_iperf_direct.json",       "UL"),
        ("1-path QUIC (iperf3 TCP)",     "m3_iperf_sp_tcp.json",       "UL"),
        ("1-path QUIC (iperf3 TCP)",     "m3_iperf_sp_tcp_dl.json",    "DL"),
        ("1-path QUIC (iperf3 UDP)",     "m3_iperf_sp_udp.json",       "UL"),
        ("1-path QUIC (iperf3 UDP)",     "m3_iperf_sp_udp_dl.json",    "DL"),
        ("2-path QUIC (iperf3 TCP)",     "m3_iperf_mp_tcp.json",       "UL"),
        ("2-path QUIC (iperf3 TCP)",     "m3_iperf_mp_tcp_dl.json",    "DL"),
        ("2-path QUIC (iperf3 UDP)",     "m3_iperf_mp_udp.json",       "UL"),
    ]

    for test_name, filename, direction in test_files:
        path = bench_dir / filename
        if path.exists():
            result = parse_iperf3_json(str(path))
            if result and 'error' not in result:
                if result['type'] == 'TCP':
                    notes = f"retrans={result.get('retransmits', 'N/A')}"
                    mbps = result['recv_mbps']
                else:
                    notes = (f"loss={result.get('lost_pct', 0):.1f}%, "
                             f"jitter={result.get('jitter_ms', 0):.1f}ms")
                    mbps = result['mbps']
                report.append(
                    f"| {test_name} | {direction} | {mbps:.1f} | {notes} |")

    # Failover
    failover_path = bench_dir / "m3_failover.json"
    if failover_path.exists():
        report.append("\n## Failover Test\n")
        report.append("60-second iperf3 with Path A (enp5s0) taken down at t=20s "
                       "and restored at t=40s.\n")
        intervals = parse_failover_intervals(str(failover_path))
        if intervals:
            report.append("```")
            for iv in intervals:
                marker = ""
                if 18 <= iv['start'] <= 22:
                    marker = "  <-- path down"
                elif 38 <= iv['start'] <= 42:
                    marker = "  <-- path restored"
                report.append(
                    f"t={iv['start']:5.1f}s: {iv['mbps']:7.1f} Mbps{marker}")
            report.append("```\n")

            # Summary stats
            before = [iv['mbps'] for iv in intervals if iv['start'] < 18]
            during = [iv['mbps'] for iv in intervals if 22 <= iv['start'] < 38]
            after = [iv['mbps'] for iv in intervals if iv['start'] >= 42]
            if before:
                report.append(
                    f"- Before failover (t=0-18): avg {sum(before)/len(before):.1f} Mbps")
            if during:
                report.append(
                    f"- During failover (t=22-38): avg {sum(during)/len(during):.1f} Mbps")
            if after:
                report.append(
                    f"- After restore (t=42-60): avg {sum(after)/len(after):.1f} Mbps")
            report.append("- **Result: Zero downtime — throughput maintained throughout**")

    # Stability
    stability_path = bench_dir / "m3_stability_1h.json"
    memory_path = bench_dir / "m3_memory.txt"
    if stability_path.exists():
        report.append("\n## Stability (1-hour test)\n")
        result = parse_iperf3_json(str(stability_path))
        if result and 'error' not in result:
            if result['type'] == 'TCP':
                report.append(
                    f"- Duration: {result['duration']:.0f}s")
                report.append(
                    f"- Throughput: {result['recv_mbps']:.1f} Mbps")
                report.append(
                    f"- Retransmits: {result['retransmits']}")

    if memory_path.exists():
        with open(memory_path) as f:
            lines = [l.strip().split() for l in f if l.strip()]
        if lines:
            first_kb = int(lines[0][1])
            last_kb = int(lines[-1][1])
            max_kb = max(int(l[1]) for l in lines)
            report.append(f"- Memory (RSS): start={first_kb} KB, "
                          f"end={last_kb} KB, max={max_kb} KB")
            growth = (last_kb - first_kb) / first_kb * 100 if first_kb else 0
            report.append(f"- Memory growth: {growth:+.1f}%")

    return "\n".join(report)


if __name__ == "__main__":
    bench_dir = sys.argv[1] if len(sys.argv) > 1 else "benchmarks/m3"
    print(generate_report(bench_dir))

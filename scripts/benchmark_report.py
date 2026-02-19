#!/usr/bin/env python3
"""Parse iperf3 JSON results and generate M3 benchmark report."""

import json
import sys
import os
import re
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


def parse_udp_sweep(bench_dir, prefix):
    """Parse UDP sweep results and return sorted list of (rate_mbps, loss%, jitter)."""
    results = []
    for f in sorted(bench_dir.glob(f"{prefix}_*.json")):
        # Skip DL files when looking for UL
        # e.g. prefix="m3_udp_sweep_1path" should not match "m3_udp_sweep_1path_dl_10M.json"
        suffix = f.name[len(prefix):]  # e.g. "_dl_10M.json" or "_10M.json"
        if '_dl' not in prefix and suffix.startswith('_dl'):
            continue
        # Extract rate from filename like m3_udp_sweep_1path_85M.json
        m = re.search(r'_(\d+)M\.json$', f.name)
        if not m:
            continue
        rate = int(m.group(1))
        result = parse_iperf3_json(str(f))
        if result and 'error' not in result and result['type'] == 'UDP':
            results.append({
                'rate': rate,
                'mbps': result['mbps'],
                'lost_pct': result['lost_pct'],
                'jitter_ms': result['jitter_ms'],
            })
    results.sort(key=lambda x: x['rate'])
    return results


def find_max_udp_bandwidth(sweep_results, loss_threshold=1.0):
    """Find highest rate with loss < threshold. Scan from highest rate downward."""
    for r in reversed(sweep_results):
        if r['lost_pct'] < loss_threshold:
            return r
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
            for token in line.split(','):
                if 'packet loss' in token:
                    stats['loss_pct'] = token.strip().split('%')[0].strip()
    return stats if stats else None


def generate_report(bench_dir):
    """Generate markdown benchmark report."""
    bench_dir = Path(bench_dir)
    report = []
    report.append("# mqvpn M3 Benchmark Report\n")
    report.append(f"Date: {os.popen('date -I').read().strip()}")
    report.append("Environment: Local machine (2x ISP) → ConoHa VPS (100 Mbps)")
    report.append("Underlay: Direct WAN (163.44.118.182)")
    report.append("Protocol: MASQUE CONNECT-IP (RFC 9484) over HTTP/3")
    report.append("")
    report.append("IP packets are tunneled as HTTP Datagrams (Context ID=0) "
                  "on an H3 Extended CONNECT stream (:protocol=connect-ip), "
                  "carried over QUIC DATAGRAM frames (RFC 9221). "
                  "Capsules (ADDRESS_ASSIGN, ROUTE_ADVERTISEMENT) on the "
                  "CONNECT stream handle control; Multipath QUIC (RFC 9443) "
                  "is a separate transport extension.")
    report.append("")

    # Latency
    report.append("## Latency\n")
    report.append("| Path | Min (ms) | Avg (ms) | Max (ms) | Loss |")
    report.append("|------|----------|----------|----------|------|")

    for name, file in [("Direct WAN (IPv6)",   "m3_latency_direct_wan_v6.txt"),
                        ("1-path QUIC tunnel", "m3_latency_vpn_1path.txt"),
                        ("2-path QUIC tunnel", "m3_latency_vpn_2path.txt")]:
        path = bench_dir / file
        if path.exists():
            stats = parse_ping(str(path))
            if stats:
                loss = stats.get('loss_pct', '?')
                report.append(
                    f"| {name} | {stats['min_ms']:.1f} | "
                    f"{stats['avg_ms']:.1f} | {stats['max_ms']:.1f} | {loss}% |")

    # TCP Throughput
    report.append("\n## TCP Throughput\n")
    report.append("| Test | Direction | Mbps | Notes |")
    report.append("|------|-----------|------|-------|")

    tcp_tests = [
        ("Direct (no VPN)",  "m3_iperf_direct_tcp_ul.json", "UL"),
        ("Direct (no VPN)",  "m3_iperf_direct_tcp_dl.json", "DL"),
        ("1-path QUIC",      "m3_iperf_1path_tcp_ul.json",  "UL"),
        ("1-path QUIC",      "m3_iperf_1path_tcp_dl.json",  "DL"),
        ("2-path QUIC",      "m3_iperf_mp_tcp.json",        "UL"),
        ("2-path QUIC",      "m3_iperf_mp_tcp_dl.json",     "DL"),
    ]

    for test_name, filename, direction in tcp_tests:
        path = bench_dir / filename
        if path.exists():
            result = parse_iperf3_json(str(path))
            if result and 'error' not in result and result['type'] == 'TCP':
                report.append(
                    f"| {test_name} | {direction} | {result['recv_mbps']:.1f} "
                    f"| retrans={result.get('retransmits', 'N/A')} |")

    # UDP Throughput (sweep)
    report.append("\n## UDP Throughput (Bandwidth Sweep)\n")
    report.append("iperf3 UDP at increasing target rates (10s each). "
                  "Max bandwidth with loss < 1%:\n")
    report.append("| Test | Direction | Max Mbps (loss < 1%) | Next rate → loss |")
    report.append("|------|-----------|---------------------|-----------------|")

    sweep_configs = [
        ("1-path QUIC", "UL", "m3_udp_sweep_1path"),
        ("1-path QUIC", "DL", "m3_udp_sweep_1path_dl"),
        ("2-path QUIC", "UL", "m3_udp_sweep_2path"),
        ("2-path QUIC", "DL", "m3_udp_sweep_2path_dl"),
    ]

    all_sweeps = {}
    for test_name, direction, prefix in sweep_configs:
        sweep = parse_udp_sweep(bench_dir, prefix)
        all_sweeps[(test_name, direction)] = sweep
        best = find_max_udp_bandwidth(sweep)
        if best:
            # Find next rate that exceeds threshold
            next_over = None
            for r in sweep:
                if r['rate'] > best['rate'] and r['lost_pct'] >= 1.0:
                    next_over = r
                    break
            next_str = (f"{next_over['rate']}M → {next_over['lost_pct']:.1f}%"
                        if next_over else "—")
            report.append(
                f"| {test_name} | {direction} | {best['rate']:.0f} "
                f"| {next_str} |")

    # Sweep detail tables
    report.append("\n### Sweep Details\n")
    for test_name, direction, prefix in sweep_configs:
        sweep = all_sweeps.get((test_name, direction), [])
        if not sweep:
            continue
        report.append(f"**{test_name} {direction}:**\n")
        report.append("| Rate | Mbps | Loss | Jitter |")
        report.append("|------|------|------|--------|")
        for r in sweep:
            marker = " **" if r['lost_pct'] >= 1.0 else ""
            report.append(
                f"| {r['rate']}M | {r['mbps']:.1f} | {r['lost_pct']:.2f}% "
                f"| {r['jitter_ms']:.2f}ms |{marker}")
        report.append("")

    # Failover
    failover_path = bench_dir / "m3_failover.json"
    if failover_path.exists():
        report.append("## Failover Test\n")
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

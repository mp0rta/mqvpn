# fuzz/corpus/tcp_lane/ — seed corpus for fuzz_tcp_lane

Six hand-crafted raw IPv4 packets, one per file (libFuzzer's plain-file
format — each file is exactly the bytes `LLVMFuzzerTestOneInput` receives).
They exist only to bootstrap libFuzzer's coverage-guided mutation; the
fuzzer generates everything else itself from these starting points.

Regenerate after a wire-format change (e.g. the classifier's parsed fields,
`mqvpn_parse_l3l4`'s accepted shapes) with the tracked generator:

```
python3 fuzz/corpus/gen_tcp_lane_corpus.py
```

It builds each packet by hand (IPv4 header with correct checksum + a TCP or
UDP payload, pure stdlib — no pcap/scapy) and overwrites the six `.bin`
files in place. Editing the packet shapes there and rerunning is the
intended regeneration path.

Contents:
- `01_syn.bin` — IPv4/TCP SYN, dst port 80, no options
- `02_data.bin` — IPv4/TCP PSH+ACK carrying an HTTP request payload
- `03_fin.bin` — IPv4/TCP FIN+ACK
- `04_ipopts_syn.bin` — IPv4/TCP SYN with a 4-byte IPv4 options word (IHL=6)
- `05_truncated.bin` — first 10 bytes only of an IPv4 header (malformed —
  exercises `mqvpn_parse_l3l4`'s short-packet rejection path)
- `06_udp.bin` — IPv4/UDP packet (DNS-shaped payload) — exercises the
  classifier's `MQVPN_LANE_DGRAM` verdict, which `fuzz_tcp_lane.c`
  deliberately does NOT feed into lwIP (only `MQVPN_LANE_TCP` packets are)

Keep this corpus small (a handful of files) — it is a bootstrap seed, not a
coverage archive. Do not commit libFuzzer's own generated/reduced corpus
files (the numerous long hex-named files it writes back into a corpus
directory it's given as an argument) — run against a scratch copy of this
directory, not this one, if you want to let it grow the corpus locally.

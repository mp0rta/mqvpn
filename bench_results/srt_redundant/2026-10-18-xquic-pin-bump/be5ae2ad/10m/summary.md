# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-18 12:33
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: 03a3749c, xquic be5ae2ad
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 10 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 427 received, 14.6% packet loss, time 5833ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 0.318 | 56961 | 153 | 0 | 4621 | 4637 | 117.55 | 11.11 | 51 | 38 |
| R2_120_mq-wlb-redundant_r1 | 0.000 | 56960 | 1 | 0 | 55602 | 90 | 116.65 | 20.56 | 82 | 82 |
| R2_120_mq-wlb-off_r2 | 0.263 | 56962 | 137 | 0 | 4386 | 4397 | 121.59 | 11.07 | 51 | 37 |
| R2_120_mq-wlb-redundant_r2 | 0.018 | 56959 | 4 | 0 | 55188 | 109 | 116.76 | 20.46 | 82 | 81 |
| R2_120_mq-wlb-off_r3 | 0.235 | 56964 | 129 | 0 | 4494 | 4539 | 118.70 | 11.10 | 51 | 37 |
| R2_120_mq-wlb-redundant_r3 | 0.040 | 56971 | 0 | 0 | 55910 | 88 | 117.52 | 20.54 | 82 | 82 |
| R3_120_mq-wlb-off_r1 | 2.607 | 56970 | 1506 | 0 | 8890 | 10187 | 81.93 | 11.73 | 37 | 56 |
| R3_120_mq-wlb-redundant_r1 | 0.000 | 56971 | 0 | 0 | 15654 | 369 | 84.43 | 13.43 | 24 | 82 |
| R3_120_mq-wlb-off_r2 | 2.038 | 56965 | 1161 | 0 | 8688 | 9981 | 79.21 | 11.75 | 31 | 62 |
| R3_120_mq-wlb-redundant_r2 | 0.000 | 56963 | 0 | 0 | 14013 | 316 | 84.94 | 13.03 | 21 | 82 |
| R3_120_mq-wlb-off_r3 | 2.891 | 56961 | 1651 | 0 | 9110 | 10494 | 80.90 | 11.75 | 39 | 53 |
| R3_120_mq-wlb-redundant_r3 | 0.000 | 56964 | 0 | 0 | 12277 | 259 | 84.25 | 12.68 | 18 | 82 |
| R4_120_mq-wlb-off_r1 | 1.694 | 56963 | 881 | 0 | 4717 | 4732 | 131.74 | 10.98 | 25 | 62 |
| R4_120_mq-wlb-redundant_r1 | 0.207 | 56965 | 64 | 0 | 41164 | 219 | 128.27 | 17.85 | 60 | 82 |
| R4_120_mq-wlb-off_r2 | 1.992 | 56969 | 1163 | 0 | 4128 | 4137 | 129.64 | 10.83 | 31 | 55 |
| R4_120_mq-wlb-redundant_r2 | 0.133 | 56964 | 68 | 0 | 40965 | 230 | 127.90 | 17.82 | 60 | 81 |
| R4_120_mq-wlb-off_r3 | 1.713 | 56963 | 962 | 0 | 4510 | 4522 | 129.12 | 10.94 | 29 | 58 |
| R4_120_mq-wlb-redundant_r3 | 0.151 | 56963 | 62 | 0 | 42663 | 235 | 125.52 | 18.13 | 62 | 82 |

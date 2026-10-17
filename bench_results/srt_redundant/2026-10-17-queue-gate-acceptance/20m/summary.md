# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-17 12:31
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: d567e5cc
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 20 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 403 received, 19.4% packet loss, time 5821ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 0.270 | 113875 | 389 | 0 | 21688 | 22015 | 123.98 | 24.50 | 134 | 63 |
| R2_120_mq-wlb-redundant_r1 | 0.032 | 113884 | 1 | 0 | 110168 | 386 | 123.15 | 40.94 | 164 | 162 |
| R2_120_mq-wlb-off_r2 | 0.442 | 113878 | 516 | 0 | 22654 | 22925 | 125.98 | 24.68 | 121 | 77 |
| R2_120_mq-wlb-redundant_r2 | 0.025 | 113879 | 11 | 0 | 110011 | 303 | 119.49 | 40.89 | 164 | 161 |
| R2_120_mq-wlb-off_r3 | 0.467 | 113877 | 558 | 0 | 22475 | 22607 | 129.08 | 24.63 | 120 | 78 |
| R2_120_mq-wlb-redundant_r3 | 0.010 | 113883 | 5 | 0 | 109869 | 303 | 119.95 | 40.90 | 164 | 161 |
| R3_120_mq-wlb-off_r1 | 4.918 | 113877 | 5644 | 0 | 22528 | 22904 | 80.27 | 23.69 | 95 | 94 |
| R3_120_mq-wlb-redundant_r1 | 0.118 | 113898 | 52 | 0 | 81076 | 10081 | 72.70 | 41.04 | 155 | 172 |
| R3_120_mq-wlb-off_r2 | 4.641 | 113884 | 5279 | 0 | 22395 | 22949 | 81.30 | 23.75 | 87 | 103 |
| R3_120_mq-wlb-redundant_r2 | 0.087 | 113889 | 52 | 0 | 18900 | 1135 | 98.43 | 24.59 | 31 | 165 |
| R3_120_mq-wlb-off_r3 | ERR | - | - | - | NA | - | - | - | - | - |
| R3_120_mq-wlb-redundant_r3 | 0.006 | 113888 | 38 | 0 | 79922 | 9784 | 72.54 | 40.98 | 155 | 171 |
| R4_120_mq-wlb-off_r1 | 2.464 | 113875 | 2718 | 0 | 18579 | 18666 | 135.61 | 23.49 | 78 | 110 |
| R4_120_mq-wlb-redundant_r1 | 0.147 | 113880 | 77 | 0 | 80491 | 628 | 134.67 | 35.46 | 121 | 161 |
| R4_120_mq-wlb-off_r2 | 2.894 | 113877 | 3230 | 0 | 17303 | 17580 | 136.12 | 23.20 | 79 | 106 |
| R4_120_mq-wlb-redundant_r2 | 0.108 | 113875 | 72 | 0 | 82123 | 468 | 132.98 | 35.81 | 123 | 162 |
| R4_120_mq-wlb-off_r3 | 2.282 | 113876 | 2514 | 0 | 18465 | 18428 | 137.00 | 23.49 | 73 | 115 |
| R4_120_mq-wlb-redundant_r3 | 0.169 | 113878 | 140 | 0 | 81775 | 635 | 134.69 | 35.76 | 122 | 162 |

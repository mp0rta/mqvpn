# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-12 17:37
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: 08bef6ac
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 50 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 376 received, 24.8% packet loss, time 5823ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 3.823 | 284829 | 10830 | 0 | 65873 | 57073 | 149.14 | 61.66 | 282 | 211 |
| R2_120_mq-wlb-redundant_r1 | 31.934 | 284837 | 91084 | 252624 | 173035 | 1426 | 1246.02 | 65.22 | 291 | 218 |
| R2_120_mq-wlb-off_r2 | 3.002 | 284831 | 8654 | 0 | 64551 | 57653 | 147.73 | 61.71 | 281 | 212 |
| R2_120_mq-wlb-redundant_r2 | 27.858 | 284838 | 79546 | 251108 | 162739 | 2075 | 1233.48 | 59.67 | 291 | 217 |
| R2_120_mq-wlb-off_r3 | 3.337 | 284834 | 9482 | 0 | 64790 | 57316 | 146.53 | 61.62 | 282 | 211 |
| R2_120_mq-wlb-redundant_r3 | 27.286 | 284835 | 77347 | 242740 | 157392 | 3089 | 1115.75 | 64.85 | 290 | 217 |
| R3_120_mq-wlb-off_r1 | 6.027 | 284812 | 17277 | 0 | 57497 | 57055 | 77.63 | 58.81 | 272 | 198 |
| R3_120_mq-wlb-redundant_r1 | 0.125 | 284823 | 537 | 0 | 147958 | 34581 | 74.03 | 104.11 | 392 | 436 |
| R3_120_mq-wlb-off_r2 | 6.046 | 284823 | 17329 | 0 | 57441 | 56996 | 78.67 | 58.79 | 272 | 199 |
| R3_120_mq-wlb-redundant_r2 | 0.185 | 284835 | 524 | 0 | 146250 | 33997 | 75.45 | 103.93 | 392 | 435 |
| R3_120_mq-wlb-off_r3 | 4.942 | 284834 | 14144 | 0 | 58380 | 57643 | 80.24 | 59.53 | 215 | 261 |
| R3_120_mq-wlb-redundant_r3 | ERR | - | - | - | NA | - | - | - | - | - |

# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-16 16:26
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: e3ddd8bf
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 50 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 416 received, 16.8% packet loss, time 5829ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 4.063 | 284827 | 11730 | 0 | 67597 | 57916 | 146.27 | 61.76 | 282 | 213 |
| R2_120_mq-wlb-redundant_r1 | 4.496 | 284811 | 12721 | 0 | 66893 | 53801 | 191.38 | 61.46 | 287 | 205 |
| R2_120_mq-wlb-off_r2 | 4.472 | 284819 | 12652 | 0 | 67402 | 56705 | 155.19 | 61.61 | 283 | 210 |
| R2_120_mq-wlb-redundant_r2 | 7.938 | 284805 | 22504 | 0 | 79330 | 55730 | 180.31 | 61.95 | 283 | 213 |
| R2_120_mq-wlb-off_r3 | 4.221 | 284826 | 11809 | 0 | 68054 | 58169 | 150.25 | 61.83 | 277 | 218 |
| R2_120_mq-wlb-redundant_r3 | 6.329 | 284815 | 17875 | 0 | 73127 | 54866 | 189.35 | 61.68 | 286 | 208 |
| R3_120_mq-wlb-off_r1 | 3.253 | 284807 | 9363 | 0 | 59048 | 58477 | 85.08 | 60.53 | 138 | 345 |
| R3_120_mq-wlb-redundant_r1 | 0.117 | 284830 | 328 | 0 | 24679 | 63 | 85.17 | 55.93 | 35 | 409 |
| R3_120_mq-wlb-off_r2 | 3.938 | 284818 | 11313 | 0 | 58949 | 58252 | 82.86 | 60.16 | 169 | 311 |
| R3_120_mq-wlb-redundant_r2 | 0.126 | 284825 | 457 | 0 | 14733 | 0 | 88.16 | 54.12 | 21 | 409 |
| R3_120_mq-wlb-off_r3 | 3.261 | 284812 | 9395 | 0 | 59085 | 58483 | 85.78 | 60.54 | 138 | 345 |
| R3_120_mq-wlb-redundant_r3 | 0.142 | 284817 | 396 | 0 | 18984 | 67 | 84.21 | 54.88 | 27 | 409 |
| R4_120_mq-wlb-off_r1 | 22.983 | 284823 | 65179 | 37028 | 93231 | 33406 | 526.29 | 55.29 | 224 | 221 |
| R4_120_mq-wlb-redundant_r1 | 21.794 | 284814 | 61932 | 33138 | 91169 | 29762 | 519.89 | 55.67 | 224 | 221 |
| R4_120_mq-wlb-off_r2 | 24.971 | 284826 | 70988 | 56236 | 95381 | 28432 | 610.82 | 54.45 | 218 | 220 |
| R4_120_mq-wlb-redundant_r2 | 24.941 | 284817 | 70896 | 44931 | 95232 | 26007 | 561.16 | 54.39 | 218 | 221 |
| R4_120_mq-wlb-off_r3 | 31.401 | 284824 | 89297 | 51744 | 116578 | 31316 | 581.45 | 55.34 | 221 | 221 |
| R4_120_mq-wlb-redundant_r3 | 24.935 | 284817 | 70732 | 53817 | 95779 | 26995 | 605.96 | 55.01 | 217 | 222 |

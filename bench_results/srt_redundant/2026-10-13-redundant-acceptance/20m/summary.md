# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-12 15:53
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: 08bef6ac
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 20 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 387 received, 22.6% packet loss, time 5816ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 0.283 | 113882 | 341 | 0 | 20149 | 20418 | 123.77 | 24.24 | 142 | 52 |
| R2_120_mq-wlb-redundant_r1 | 0.028 | 113874 | 11 | 0 | 110247 | 328 | 118.87 | 40.99 | 163 | 162 |
| R2_120_mq-wlb-off_r2 | 0.508 | 113876 | 530 | 0 | 22038 | 22148 | 127.37 | 24.54 | 126 | 71 |
| R2_120_mq-wlb-redundant_r2 | 0.069 | 113876 | 7 | 0 | 110480 | 290 | 121.09 | 40.99 | 163 | 162 |
| R2_120_mq-wlb-off_r3 | 0.406 | 113878 | 412 | 0 | 20746 | 21243 | 124.39 | 24.38 | 137 | 58 |
| R2_120_mq-wlb-redundant_r3 | 0.019 | 113886 | 1 | 0 | 110346 | 302 | 122.18 | 41.04 | 163 | 162 |
| R3_120_mq-wlb-off_r1 | 6.931 | 113870 | 7887 | 0 | 22148 | 22364 | 77.17 | 23.20 | 122 | 63 |
| R3_120_mq-wlb-redundant_r1 | 0.000 | 113869 | 34 | 0 | 80668 | 10321 | 72.25 | 41.02 | 154 | 172 |
| R3_120_mq-wlb-off_r2 | 4.391 | 113882 | 4998 | 0 | 22380 | 22918 | 81.96 | 23.80 | 85 | 105 |
| R3_120_mq-wlb-redundant_r2 | 0.000 | 113873 | 36 | 0 | 81119 | 10807 | 73.11 | 41.13 | 155 | 172 |
| R3_120_mq-wlb-off_r3 | 5.231 | 113864 | 6002 | 0 | 22419 | 22763 | 79.35 | 23.61 | 93 | 95 |
| R3_120_mq-wlb-redundant_r3 | 0.000 | 113868 | 31 | 0 | 80575 | 10276 | 72.93 | 41.00 | 154 | 172 |
| R4_120_mq-wlb-off_r1 | 2.490 | 113871 | 2823 | 0 | 18999 | 19077 | 136.03 | 23.54 | 79 | 109 |
| R4_120_mq-wlb-redundant_r1 | 1.108 | 113870 | 1186 | 0 | 80292 | 934 | 165.56 | 35.08 | 118 | 158 |
| R4_120_mq-wlb-off_r2 | 2.388 | 113870 | 2643 | 0 | 17848 | 17979 | 138.70 | 23.38 | 74 | 113 |
| R4_120_mq-wlb-redundant_r2 | 0.130 | 113871 | 117 | 0 | 83862 | 833 | 127.80 | 36.18 | 124 | 162 |
| R4_120_mq-wlb-off_r3 | 2.888 | 113868 | 3253 | 0 | 17051 | 17121 | 137.64 | 23.13 | 82 | 103 |
| R4_120_mq-wlb-redundant_r3 | 0.148 | 113876 | 66 | 0 | 81037 | 597 | 134.99 | 35.61 | 120 | 162 |

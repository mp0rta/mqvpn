# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-16 16:05
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: e3ddd8bf
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 20 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 412 received, 17.6% packet loss, time 5823ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 0.533 | 113871 | 611 | 0 | 21981 | 22118 | 127.58 | 24.54 | 125 | 72 |
| R2_120_mq-wlb-redundant_r1 | 0.028 | 113875 | 6 | 0 | 110074 | 318 | 121.76 | 41.00 | 164 | 162 |
| R2_120_mq-wlb-off_r2 | 0.335 | 113876 | 349 | 0 | 20129 | 20416 | 126.92 | 24.23 | 137 | 58 |
| R2_120_mq-wlb-redundant_r2 | 0.000 | 113877 | 9 | 0 | 110121 | 299 | 121.66 | 40.98 | 164 | 162 |
| R2_120_mq-wlb-off_r3 | 0.207 | 113873 | 245 | 0 | 19177 | 19727 | 123.39 | 24.11 | 143 | 50 |
| R2_120_mq-wlb-redundant_r3 | 0.022 | 113874 | 9 | 0 | 110605 | 269 | 124.36 | 41.03 | 164 | 163 |
| R3_120_mq-wlb-off_r1 | 5.331 | 113871 | 6067 | 0 | 22350 | 22704 | 76.61 | 23.58 | 100 | 88 |
| R3_120_mq-wlb-redundant_r1 | 0.000 | 113872 | 42 | 0 | 80530 | 10447 | 72.43 | 41.06 | 155 | 172 |
| R3_120_mq-wlb-off_r2 | 4.337 | 113868 | 4937 | 0 | 22534 | 22973 | 80.45 | 23.83 | 81 | 109 |
| R3_120_mq-wlb-redundant_r2 | 0.022 | 113873 | 64 | 0 | 25282 | 1726 | 84.32 | 26.25 | 43 | 165 |
| R3_120_mq-wlb-off_r3 | 5.265 | 113874 | 5998 | 0 | 22486 | 22828 | 79.76 | 23.62 | 95 | 93 |
| R3_120_mq-wlb-redundant_r3 | 0.004 | 113872 | 78 | 0 | 79696 | 11041 | 73.06 | 41.11 | 155 | 172 |
| R4_120_mq-wlb-off_r1 | 2.599 | 113873 | 3040 | 0 | 18630 | 18777 | 136.41 | 23.43 | 81 | 106 |
| R4_120_mq-wlb-redundant_r1 | 0.129 | 113874 | 226 | 0 | 82204 | 863 | 135.58 | 35.85 | 122 | 163 |
| R4_120_mq-wlb-off_r2 | 2.194 | 113868 | 2460 | 0 | 18010 | 18151 | 136.51 | 23.45 | 75 | 113 |
| R4_120_mq-wlb-redundant_r2 | 0.185 | 113877 | 131 | 0 | 82597 | 772 | 131.95 | 35.94 | 122 | 163 |
| R4_120_mq-wlb-off_r3 | 2.615 | 113878 | 3037 | 0 | 18327 | 18197 | 134.05 | 23.35 | 80 | 108 |
| R4_120_mq-wlb-redundant_r3 | 0.121 | 113876 | 71 | 0 | 82178 | 703 | 134.16 | 35.84 | 122 | 162 |

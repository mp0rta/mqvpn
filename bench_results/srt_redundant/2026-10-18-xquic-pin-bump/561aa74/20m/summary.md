# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-18 13:16
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: 03a3749c, xquic 561aa74
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 20 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 395 received, 21% packet loss, time 5831ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 0.407 | 113902 | 453 | 0 | 22053 | 22258 | 125.33 | 24.56 | 129 | 68 |
| R2_120_mq-wlb-redundant_r1 | 0.004 | 113895 | 4 | 0 | 109367 | 293 | 121.92 | 40.90 | 164 | 161 |
| R2_120_mq-wlb-off_r2 | 0.395 | 113908 | 438 | 0 | 21108 | 21322 | 126.93 | 24.40 | 136 | 59 |
| R2_120_mq-wlb-redundant_r2 | 0.032 | 113882 | 7 | 0 | 109859 | 332 | 123.44 | 40.92 | 164 | 162 |
| R2_120_mq-wlb-off_r3 | 0.421 | 113899 | 446 | 0 | 20959 | 21269 | 126.85 | 24.38 | 137 | 58 |
| R2_120_mq-wlb-redundant_r3 | 0.020 | 113889 | 7 | 0 | 110227 | 287 | 122.06 | 40.94 | 164 | 162 |
| R3_120_mq-wlb-off_r1 | 4.918 | 113895 | 5621 | 0 | 22406 | 22858 | 79.38 | 23.68 | 94 | 95 |
| R3_120_mq-wlb-redundant_r1 | 0.159 | 113893 | 66 | 0 | 80293 | 10630 | 73.79 | 41.13 | 155 | 172 |
| R3_120_mq-wlb-off_r2 | 5.348 | 113896 | 6079 | 0 | 22461 | 22780 | 81.35 | 23.59 | 100 | 88 |
| R3_120_mq-wlb-redundant_r2 | 0.005 | 113894 | 47 | 0 | 9780 | 241 | 86.50 | 22.38 | 14 | 164 |
| R3_120_mq-wlb-off_r3 | 4.029 | 113897 | 4629 | 0 | 22429 | 23050 | 81.87 | 23.89 | 78 | 112 |
| R3_120_mq-wlb-redundant_r3 | 0.011 | 113886 | 48 | 0 | 54044 | 5817 | 78.56 | 33.70 | 100 | 168 |
| R4_120_mq-wlb-off_r1 | 3.286 | 113885 | 3668 | 0 | 17537 | 17546 | 136.06 | 23.15 | 86 | 100 |
| R4_120_mq-wlb-redundant_r1 | 0.144 | 113891 | 111 | 0 | 81034 | 507 | 134.36 | 35.62 | 121 | 162 |
| R4_120_mq-wlb-off_r2 | 2.771 | 113896 | 3120 | 0 | 17891 | 17996 | 136.69 | 23.30 | 77 | 109 |
| R4_120_mq-wlb-redundant_r2 | 0.153 | 113898 | 76 | 0 | 80973 | 670 | 133.97 | 35.62 | 121 | 162 |
| R4_120_mq-wlb-off_r3 | 2.678 | 113894 | 2945 | 0 | 18184 | 18085 | 135.42 | 23.34 | 79 | 108 |
| R4_120_mq-wlb-redundant_r3 | 0.115 | 113887 | 71 | 0 | 80283 | 649 | 130.70 | 35.61 | 121 | 162 |

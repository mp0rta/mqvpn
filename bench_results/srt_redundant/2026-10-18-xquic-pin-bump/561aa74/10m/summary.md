# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-18 12:54
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: 03a3749c, xquic 561aa74
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 10 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 433 received, 13.4% packet loss, time 5836ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 0.262 | 56962 | 153 | 0 | 3759 | 3762 | 116.55 | 10.96 | 56 | 31 |
| R2_120_mq-wlb-redundant_r1 | ERR | - | - | - | NA | - | - | - | - | - |
| R2_120_mq-wlb-off_r2 | 0.291 | 56963 | 156 | 0 | 3246 | 3250 | 118.81 | 10.86 | 59 | 27 |
| R2_120_mq-wlb-redundant_r2 | 0.000 | 56963 | 0 | 0 | 55930 | 94 | 115.21 | 20.56 | 82 | 82 |
| R2_120_mq-wlb-off_r3 | 0.265 | 56962 | 160 | 0 | 4362 | 4378 | 119.25 | 11.07 | 51 | 36 |
| R2_120_mq-wlb-redundant_r3 | 0.021 | 56963 | 1 | 0 | 55470 | 95 | 114.03 | 20.48 | 82 | 81 |
| R3_120_mq-wlb-off_r1 | 3.432 | 56964 | 1976 | 0 | 9307 | 10184 | 81.10 | 11.69 | 39 | 53 |
| R3_120_mq-wlb-redundant_r1 | 0.000 | 56965 | 0 | 0 | 11108 | 349 | 84.97 | 12.54 | 17 | 82 |
| R3_120_mq-wlb-off_r2 | 2.791 | 56963 | 1595 | 0 | 8881 | 10301 | 77.25 | 11.72 | 40 | 53 |
| R3_120_mq-wlb-redundant_r2 | 0.000 | 56964 | 0 | 0 | 11174 | 341 | 85.25 | 12.48 | 17 | 82 |
| R3_120_mq-wlb-off_r3 | 3.134 | 56963 | 1807 | 0 | 8960 | 9921 | 81.29 | 11.67 | 38 | 54 |
| R3_120_mq-wlb-redundant_r3 | 0.000 | 56959 | 0 | 0 | 28959 | 1343 | 78.77 | 16.53 | 48 | 83 |
| R4_120_mq-wlb-off_r1 | 1.662 | 56969 | 978 | 0 | 5183 | 5109 | 129.37 | 11.05 | 26 | 62 |
| R4_120_mq-wlb-redundant_r1 | 0.184 | 56975 | 66 | 0 | 41919 | 217 | 123.89 | 17.99 | 61 | 82 |
| R4_120_mq-wlb-off_r2 | 1.801 | 56974 | 1015 | 0 | 4752 | 4755 | 131.54 | 10.98 | 28 | 59 |
| R4_120_mq-wlb-redundant_r2 | 0.137 | 56973 | 63 | 0 | 41194 | 236 | 122.58 | 17.84 | 60 | 82 |
| R4_120_mq-wlb-off_r3 | 1.543 | 56971 | 866 | 0 | 4461 | 4476 | 132.70 | 10.95 | 29 | 58 |
| R4_120_mq-wlb-redundant_r3 | 0.142 | 56976 | 54 | 0 | 42327 | 172 | 124.26 | 18.06 | 62 | 82 |

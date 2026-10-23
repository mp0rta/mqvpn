# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-16 15:43
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: e3ddd8bf
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 10 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 385 received, 23% packet loss, time 5821ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 0.295 | 56968 | 172 | 0 | 3994 | 4001 | 117.30 | 11.00 | 55 | 32 |
| R2_120_mq-wlb-redundant_r1 | 0.016 | 56964 | 3 | 0 | 55893 | 114 | 113.92 | 20.55 | 82 | 82 |
| R2_120_mq-wlb-off_r2 | 0.239 | 56961 | 145 | 0 | 4143 | 4174 | 118.06 | 11.03 | 53 | 34 |
| R2_120_mq-wlb-redundant_r2 | 0.000 | 56961 | 2 | 0 | 55840 | 114 | 116.40 | 20.55 | 82 | 82 |
| R2_120_mq-wlb-off_r3 | 0.272 | 56962 | 155 | 0 | 3530 | 3535 | 119.60 | 10.91 | 57 | 30 |
| R2_120_mq-wlb-redundant_r3 | 0.068 | 56966 | 5 | 0 | 55735 | 121 | 114.95 | 20.54 | 82 | 81 |
| R3_120_mq-wlb-off_r1 | 3.292 | 56960 | 1897 | 0 | 9196 | 10486 | 80.90 | 11.72 | 42 | 51 |
| R3_120_mq-wlb-redundant_r1 | 0.000 | 56961 | 0 | 0 | 10815 | 143 | 85.43 | 12.36 | 16 | 82 |
| R3_120_mq-wlb-off_r2 | 2.928 | 56960 | 1682 | 0 | 9012 | 10388 | 81.84 | 11.73 | 39 | 53 |
| R3_120_mq-wlb-redundant_r2 | 0.000 | 56961 | 0 | 0 | 33581 | 1493 | 77.03 | 17.55 | 56 | 83 |
| R3_120_mq-wlb-off_r3 | 3.336 | 56962 | 1901 | 0 | 9179 | 10470 | 79.68 | 11.70 | 41 | 51 |
| R3_120_mq-wlb-redundant_r3 | 0.000 | 56962 | 0 | 0 | 8887 | 71 | 86.03 | 11.95 | 13 | 82 |
| R4_120_mq-wlb-off_r1 | 2.486 | 56964 | 1394 | 0 | 4010 | 4016 | 128.83 | 10.77 | 34 | 51 |
| R4_120_mq-wlb-redundant_r1 | 0.147 | 56963 | 62 | 0 | 41285 | 206 | 127.24 | 17.89 | 60 | 82 |
| R4_120_mq-wlb-off_r2 | 1.989 | 56962 | 1124 | 0 | 4529 | 4540 | 131.51 | 10.92 | 30 | 57 |
| R4_120_mq-wlb-redundant_r2 | 0.119 | 56961 | 46 | 0 | 41808 | 196 | 126.27 | 18.00 | 61 | 82 |
| R4_120_mq-wlb-off_r3 | 2.136 | 56963 | 1212 | 0 | 4436 | 4444 | 133.74 | 10.89 | 30 | 56 |
| R4_120_mq-wlb-redundant_r3 | 0.079 | 56964 | 82 | 0 | 41244 | 242 | 126.25 | 17.83 | 60 | 82 |

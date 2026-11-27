# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-12 15:32
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: 08bef6ac
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 10 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 394 received, 21.2% packet loss, time 5825ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 0.305 | 56963 | 164 | 0 | 4692 | 4701 | 116.61 | 11.12 | 50 | 38 |
| R2_120_mq-wlb-redundant_r1 | 0.000 | 56963 | 1 | 0 | 55445 | 98 | 115.93 | 20.56 | 82 | 82 |
| R2_120_mq-wlb-off_r2 | 0.297 | 56964 | 145 | 0 | 4053 | 4063 | 119.10 | 11.01 | 53 | 34 |
| R2_120_mq-wlb-redundant_r2 | 0.000 | 56960 | 0 | 0 | 56033 | 99 | 113.62 | 20.56 | 82 | 81 |
| R2_120_mq-wlb-off_r3 | 0.277 | 56962 | 163 | 0 | 4749 | 4763 | 120.29 | 11.13 | 48 | 40 |
| R2_120_mq-wlb-redundant_r3 | 0.051 | 56963 | 1 | 0 | 55666 | 94 | 114.32 | 20.55 | 82 | 82 |
| R3_120_mq-wlb-off_r1 | ERR | - | - | - | NA | - | - | - | - | - |
| R3_120_mq-wlb-redundant_r1 | 0.000 | 56960 | 0 | 0 | 25610 | 636 | 82.05 | 15.40 | 39 | 82 |
| R3_120_mq-wlb-off_r2 | 5.163 | 56962 | 2966 | 0 | 9092 | 10321 | 78.35 | 11.48 | 55 | 36 |
| R3_120_mq-wlb-redundant_r2 | 0.000 | 56963 | 0 | 0 | 24732 | 482 | 82.72 | 15.18 | 38 | 82 |
| R3_120_mq-wlb-off_r3 | ERR | - | - | - | NA | - | - | - | - | - |
| R3_120_mq-wlb-redundant_r3 | ERR | - | - | - | NA | - | - | - | - | - |
| R4_120_mq-wlb-off_r1 | 1.796 | 56966 | 992 | 0 | 4516 | 4518 | 132.38 | 10.94 | 30 | 57 |
| R4_120_mq-wlb-redundant_r1 | 0.191 | 56966 | 54 | 0 | 42342 | 178 | 126.40 | 18.06 | 62 | 82 |
| R4_120_mq-wlb-off_r2 | 2.012 | 56970 | 1041 | 0 | 4453 | 4457 | 130.64 | 10.92 | 30 | 57 |
| R4_120_mq-wlb-redundant_r2 | 0.065 | 56968 | 64 | 0 | 41837 | 243 | 133.67 | 17.97 | 61 | 82 |
| R4_120_mq-wlb-off_r3 | 2.196 | 56975 | 1212 | 0 | 4124 | 4115 | 130.62 | 10.82 | 32 | 54 |
| R4_120_mq-wlb-redundant_r3 | 0.161 | 56971 | 49 | 0 | 42566 | 212 | 126.64 | 18.10 | 62 | 82 |

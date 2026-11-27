# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-17 13:03
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: d567e5cc
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 20 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 388 received, 22.4% packet loss, time 5830ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R3_120_mq-wlb-off_r1 | 5.364 | 113880 | 6188 | 0 | 22423 | 22779 | 79.02 | 21.74 | 101 | 87 |
| R3_120_mq-wlb-redundant_r1 | 0.000 | 113880 | 27 | 0 | 7601 | 227 | 86.82 | 21.99 | 10 | 164 |
| R3_120_mq-wlb-off_r2 | 5.076 | 113879 | 5776 | 0 | 22506 | 22854 | 80.40 | 23.66 | 95 | 93 |
| R3_120_mq-wlb-redundant_r2 | 0.058 | 113879 | 64 | 0 | 13543 | 279 | 86.57 | 23.08 | 19 | 164 |
| R3_120_mq-wlb-off_r3 | 5.356 | 113870 | 6142 | 0 | 22482 | 22756 | 79.29 | 23.59 | 102 | 86 |
| R3_120_mq-wlb-redundant_r3 | 0.023 | 113876 | 61 | 0 | 80507 | 10557 | 73.30 | 41.06 | 155 | 172 |

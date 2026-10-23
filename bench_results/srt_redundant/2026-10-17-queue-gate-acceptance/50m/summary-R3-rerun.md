# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-17 13:10
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: d567e5cc
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 50 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 416 received, 16.8% packet loss, time 5831ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R3_120_mq-wlb-off_r1 | 2.393 | 284833 | 6908 | 0 | 59834 | 58977 | 86.52 | 61.16 | 92 | 395 |
| R3_120_mq-wlb-redundant_r1 | 0.000 | 284828 | 11 | 0 | 31779 | 661 | 83.98 | 57.68 | 48 | 410 |
| R3_120_mq-wlb-off_r2 | 1.862 | 284836 | 5292 | 0 | 59818 | 59306 | 89.23 | 61.55 | 61 | 429 |
| R3_120_mq-wlb-redundant_r2 | 0.021 | 284832 | 54 | 0 | 12405 | 208 | 101.99 | 53.79 | 17 | 410 |
| R3_120_mq-wlb-off_r3 | 4.434 | 284827 | 12632 | 0 | 58215 | 58021 | 81.01 | 59.76 | 201 | 277 |
| R3_120_mq-wlb-redundant_r3 | 0.039 | 284855 | 209 | 0 | 45740 | 658 | 89.52 | 60.02 | 67 | 410 |

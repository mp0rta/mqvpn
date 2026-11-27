# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-17 12:55
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: d567e5cc
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 10 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 399 received, 20.2% packet loss, time 5834ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R3_120_mq-wlb-off_r1 | 3.521 | 56966 | 2006 | 0 | 9224 | 10213 | 80.31 | 11.67 | 41 | 51 |
| R3_120_mq-wlb-redundant_r1 | ERR | - | - | - | NA | - | - | - | - | - |
| R3_120_mq-wlb-off_r2 | 3.358 | 56963 | 1918 | 0 | 9003 | 9925 | 81.27 | 11.65 | 40 | 52 |
| R3_120_mq-wlb-redundant_r2 | 0.000 | 56961 | 0 | 0 | 20220 | 877 | 81.66 | 14.57 | 33 | 83 |
| R3_120_mq-wlb-off_r3 | ERR | - | - | - | NA | - | - | - | - | - |
| R3_120_mq-wlb-redundant_r3 | ERR | - | - | - | NA | - | - | - | - | - |

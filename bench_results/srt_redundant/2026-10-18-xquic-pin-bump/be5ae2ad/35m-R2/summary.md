# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-18 14:48
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: 03a3749c, xquic be5ae2ad
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 35 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 0.614 | 199521 | 1119 | 0 | 41720 | 41941 | 133.24 | 43.55 | 214 | 135 |
| R2_120_mq-wlb-redundant_r1 | 1.520 | 199535 | 3150 | 0 | 54980 | 35904 | 149.04 | 45.67 | 217 | 149 |
| R2_120_mq-wlb-off_r2 | 1.215 | 199554 | 2369 | 0 | 42909 | 41787 | 135.86 | 43.53 | 205 | 144 |
| R2_120_mq-wlb-redundant_r2 | 0.843 | 199520 | 1700 | 0 | 52836 | 36776 | 149.59 | 45.56 | 222 | 142 |
| R2_120_mq-wlb-off_r3 | 0.745 | 199517 | 1521 | 0 | 42232 | 42020 | 133.51 | 43.58 | 209 | 140 |
| R2_120_mq-wlb-redundant_r3 | 2.044 | 199514 | 4041 | 0 | 63153 | 33137 | 169.50 | 47.12 | 232 | 144 |

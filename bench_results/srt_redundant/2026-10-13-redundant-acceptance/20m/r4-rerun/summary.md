# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-12 16:11
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: 08bef6ac
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 20 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R4_120_mq-wlb-redundant_r1 | 0.169 | 113876 | 94 | 0 | 80389 | 599 | 133.08 | 35.59 | 120 | 163 |
| R4_120_mq-wlb-redundant_r2 | 0.164 | 113877 | 85 | 0 | 84064 | 816 | 134.45 | 36.18 | 125 | 162 |
| R4_120_mq-wlb-redundant_r3 | 0.143 | 113879 | 93 | 0 | 83962 | 742 | 136.58 | 36.18 | 124 | 163 |

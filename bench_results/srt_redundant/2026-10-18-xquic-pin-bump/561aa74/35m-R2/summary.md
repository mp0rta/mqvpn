# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-18 14:41
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: 03a3749c, xquic 561aa74
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 35 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 0.866 | 199531 | 1663 | 0 | 42110 | 41758 | 133.40 | 43.53 | 204 | 145 |
| R2_120_mq-wlb-redundant_r1 | 0.795 | 199533 | 1425 | 0 | 131979 | 3479 | 166.83 | 60.69 | 286 | 196 |
| R2_120_mq-wlb-off_r2 | 2.162 | 199531 | 4229 | 0 | 44299 | 41682 | 139.76 | 43.50 | 172 | 177 |
| R2_120_mq-wlb-redundant_r2 | 0.532 | 199527 | 928 | 0 | 133698 | 3870 | 169.07 | 61.28 | 287 | 199 |
| R2_120_mq-wlb-off_r3 | 0.831 | 199512 | 1572 | 0 | 42327 | 42043 | 133.79 | 43.57 | 207 | 142 |
| R2_120_mq-wlb-redundant_r3 | 0.530 | 199517 | 982 | 0 | 131082 | 2531 | 164.95 | 60.47 | 286 | 194 |

# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-18 14:18
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: 03a3749c, xquic 561aa74
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 50 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 404 received, 19.2% packet loss, time 5845ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 5.266 | 284857 | 14831 | 0 | 69254 | 56405 | 153.05 | 61.54 | 283 | 210 |
| R2_120_mq-wlb-redundant_r1 | 5.999 | 284884 | 16855 | 0 | 71448 | 55098 | 171.19 | 61.57 | 283 | 210 |
| R2_120_mq-wlb-off_r2 | 3.797 | 284886 | 10746 | 0 | 64783 | 56050 | 156.15 | 61.49 | 284 | 208 |
| R2_120_mq-wlb-redundant_r2 | 4.936 | 284829 | 14010 | 0 | 65192 | 51881 | 177.85 | 61.00 | 290 | 198 |
| R2_120_mq-wlb-off_r3 | 4.561 | 284827 | 12871 | 0 | 66941 | 56043 | 148.92 | 61.49 | 285 | 207 |
| R2_120_mq-wlb-redundant_r3 | 4.133 | 284848 | 11712 | 0 | 66405 | 55229 | 171.85 | 61.55 | 282 | 211 |
| R3_120_mq-wlb-off_r1 | 3.300 | 284869 | 9016 | 0 | 59544 | 58729 | 86.01 | 60.71 | 129 | 356 |
| R3_120_mq-wlb-redundant_r1 | 0.085 | 284888 | 335 | 0 | 11742 | 329 | 88.31 | 53.62 | 16 | 409 |
| R3_120_mq-wlb-off_r2 | 2.943 | 284844 | 8463 | 0 | 59325 | 58770 | 86.09 | 60.76 | 130 | 355 |
| R3_120_mq-wlb-redundant_r2 | 0.141 | 284861 | 498 | 0 | 20630 | 407 | 88.72 | 55.26 | 29 | 409 |
| R3_120_mq-wlb-off_r3 | 2.213 | 284884 | 6405 | 0 | 60162 | 59434 | 87.47 | 61.34 | 85 | 403 |
| R3_120_mq-wlb-redundant_r3 | 0.020 | 284877 | 59 | 0 | 11888 | 313 | 88.84 | 53.69 | 17 | 410 |
| R4_120_mq-wlb-off_r1 | 29.166 | 284874 | 83248 | 99874 | 99320 | 21889 | 861.80 | 52.45 | 203 | 221 |
| R4_120_mq-wlb-redundant_r1 | 24.362 | 284837 | 69265 | 58113 | 93109 | 27974 | 612.21 | 54.99 | 218 | 219 |
| R4_120_mq-wlb-off_r2 | 21.290 | 284806 | 60848 | 23260 | 87563 | 31907 | 433.53 | 55.52 | 224 | 219 |
| R4_120_mq-wlb-redundant_r2 | 25.860 | 284812 | 73760 | 46105 | 99389 | 28654 | 563.60 | 55.17 | 220 | 219 |
| R4_120_mq-wlb-off_r3 | 27.859 | 284816 | 79345 | 40384 | 108803 | 33046 | 533.20 | 55.91 | 224 | 220 |
| R4_120_mq-wlb-redundant_r3 | 26.432 | 284843 | 75179 | 69693 | 94223 | 22768 | 654.32 | 54.06 | 212 | 219 |

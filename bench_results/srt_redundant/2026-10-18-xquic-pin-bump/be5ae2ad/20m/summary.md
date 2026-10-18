# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-18 13:36
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: 03a3749c, xquic be5ae2ad
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 20 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 393 received, 21.4% packet loss, time 5825ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 0.189 | 113890 | 282 | 0 | 21177 | 21730 | 126.49 | 24.44 | 133 | 63 |
| R2_120_mq-wlb-redundant_r1 | 0.052 | 113883 | 54 | 0 | 101096 | 624 | 118.23 | 39.11 | 164 | 147 |
| R2_120_mq-wlb-off_r2 | 0.358 | 113879 | 432 | 0 | 22573 | 22741 | 125.29 | 24.66 | 128 | 70 |
| R2_120_mq-wlb-redundant_r2 | 0.043 | 113879 | 9 | 0 | 108877 | 269 | 121.30 | 40.74 | 164 | 160 |
| R2_120_mq-wlb-off_r3 | 0.386 | 113878 | 414 | 0 | 21285 | 21802 | 127.09 | 24.48 | 135 | 61 |
| R2_120_mq-wlb-redundant_r3 | 0.028 | 113876 | 4 | 0 | 109647 | 288 | 118.99 | 40.88 | 164 | 161 |
| R3_120_mq-wlb-off_r1 | 3.597 | 113874 | 4182 | 0 | 22464 | 23030 | 83.49 | 22.11 | 71 | 120 |
| R3_120_mq-wlb-redundant_r1 | 0.056 | 113884 | 62 | 0 | 24242 | 713 | 85.23 | 25.58 | 39 | 164 |
| R3_120_mq-wlb-off_r2 | ERR | - | - | - | NA | - | - | - | - | - |
| R3_120_mq-wlb-redundant_r2 | 0.050 | 113875 | 54 | 0 | 26519 | 722 | 85.50 | 26.01 | 42 | 164 |
| R3_120_mq-wlb-off_r3 | 4.141 | 113871 | 4746 | 0 | 22508 | 23035 | 82.99 | 23.87 | 77 | 113 |
| R3_120_mq-wlb-redundant_r3 | 0.000 | 113871 | 39 | 0 | 30153 | 1107 | 84.77 | 27.14 | 51 | 165 |
| R4_120_mq-wlb-off_r1 | 2.287 | 113886 | 2536 | 0 | 19051 | 19135 | 140.57 | 23.61 | 73 | 116 |
| R4_120_mq-wlb-redundant_r1 | 0.191 | 113880 | 131 | 0 | 81383 | 918 | 133.92 | 35.71 | 122 | 162 |
| R4_120_mq-wlb-off_r2 | 2.616 | 113893 | 2956 | 0 | 18709 | 18771 | 138.44 | 23.48 | 81 | 107 |
| R4_120_mq-wlb-redundant_r2 | 0.178 | 113890 | 139 | 0 | 80875 | 551 | 136.60 | 35.61 | 121 | 162 |
| R4_120_mq-wlb-off_r3 | 2.729 | 113878 | 3085 | 0 | 17997 | 17911 | 138.24 | 23.34 | 74 | 113 |
| R4_120_mq-wlb-redundant_r3 | 0.161 | 113871 | 114 | 0 | 81751 | 726 | 133.28 | 35.76 | 122 | 162 |

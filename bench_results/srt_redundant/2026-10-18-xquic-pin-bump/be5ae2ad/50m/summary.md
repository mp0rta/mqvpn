# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-18 13:57
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: 03a3749c, xquic be5ae2ad
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 50 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 415 received, 17% packet loss, time 5830ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 6.612 | 284832 | 18734 | 0 | 72047 | 54518 | 194.80 | 61.11 | 283 | 204 |
| R2_120_mq-wlb-redundant_r1 | 12.278 | 284809 | 34904 | 0 | 87417 | 52936 | 208.48 | 60.89 | 282 | 204 |
| R2_120_mq-wlb-off_r2 | 11.067 | 284837 | 31296 | 0 | 82162 | 52197 | 218.81 | 60.56 | 279 | 204 |
| R2_120_mq-wlb-redundant_r2 | 8.868 | 284844 | 24982 | 0 | 75999 | 50683 | 242.56 | 60.50 | 282 | 200 |
| R2_120_mq-wlb-off_r3 | 10.084 | 284850 | 28528 | 0 | 80579 | 53442 | 210.14 | 60.80 | 282 | 203 |
| R2_120_mq-wlb-redundant_r3 | 9.636 | 284854 | 27376 | 0 | 78546 | 50522 | 256.27 | 60.56 | 282 | 201 |
| R3_120_mq-wlb-off_r1 | 2.601 | 284843 | 7498 | 0 | 59142 | 58981 | 86.70 | 60.93 | 112 | 374 |
| R3_120_mq-wlb-redundant_r1 | 0.135 | 284839 | 479 | 0 | 15067 | 318 | 88.01 | 54.22 | 21 | 409 |
| R3_120_mq-wlb-off_r2 | 4.105 | 284811 | 11784 | 0 | 58613 | 58047 | 82.83 | 60.01 | 182 | 297 |
| R3_120_mq-wlb-redundant_r2 | 0.239 | 284833 | 688 | 0 | 29940 | 619 | 101.21 | 56.98 | 43 | 409 |
| R3_120_mq-wlb-off_r3 | ERR | - | - | - | NA | - | - | - | - | - |
| R3_120_mq-wlb-redundant_r3 | 0.218 | 284843 | 709 | 0 | 20626 | 402 | 88.14 | 55.22 | 29 | 409 |
| R4_120_mq-wlb-off_r1 | 38.755 | 284846 | 110581 | 166295 | 115848 | 8881 | 1130.78 | 50.90 | 202 | 203 |
| R4_120_mq-wlb-redundant_r1 | 40.852 | 284827 | 116550 | 169763 | 124220 | 9253 | 1151.33 | 51.39 | 206 | 202 |
| R4_120_mq-wlb-off_r2 | 38.865 | 284884 | 110424 | 161143 | 118439 | 11147 | 1076.28 | 51.37 | 203 | 206 |
| R4_120_mq-wlb-redundant_r2 | 38.437 | 284825 | 109670 | 200132 | 115650 | 7247 | 1328.49 | 50.63 | 198 | 205 |
| R4_120_mq-wlb-off_r3 | 39.275 | 284834 | 111932 | 189453 | 116540 | 7815 | 1232.11 | 50.84 | 199 | 205 |
| R4_120_mq-wlb-redundant_r3 | 38.644 | 284868 | 109918 | 162907 | 117174 | 8786 | 1120.84 | 51.26 | 202 | 206 |

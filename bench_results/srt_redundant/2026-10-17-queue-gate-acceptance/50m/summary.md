# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-17 12:51
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: d567e5cc
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 50 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 398 received, 20.4% packet loss, time 5828ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 3.264 | 284844 | 9166 | 0 | 64433 | 56819 | 167.51 | 61.61 | 281 | 211 |
| R2_120_mq-wlb-redundant_r1 | 3.902 | 284827 | 11037 | 0 | 65807 | 55332 | 171.07 | 61.62 | 281 | 212 |
| R2_120_mq-wlb-off_r2 | 3.699 | 284840 | 10372 | 0 | 65487 | 56623 | 148.97 | 61.56 | 283 | 210 |
| R2_120_mq-wlb-redundant_r2 | 4.830 | 285006 | 13387 | 0 | 68587 | 55618 | 159.48 | 61.61 | 282 | 212 |
| R2_120_mq-wlb-off_r3 | 7.230 | 284846 | 20454 | 0 | 75740 | 56939 | 144.75 | 61.64 | 281 | 212 |
| R2_120_mq-wlb-redundant_r3 | 6.261 | 284841 | 17765 | 0 | 73380 | 53337 | 193.29 | 61.66 | 291 | 201 |
| R3_120_mq-wlb-off_r1 | 4.826 | 284849 | 13749 | 0 | 58034 | 57758 | 80.00 | 59.53 | 219 | 257 |
| R3_120_mq-wlb-redundant_r1 | 0.309 | 284844 | 980 | 0 | 26210 | 633 | 88.85 | 56.28 | 38 | 408 |
| R3_120_mq-wlb-off_r2 | ERR | - | - | - | NA | - | - | - | - | - |
| R3_120_mq-wlb-redundant_r2 | ERR | - | - | - | NA | - | - | - | - | - |
| R3_120_mq-wlb-off_r3 | 2.699 | 284845 | 7791 | 0 | 59530 | 58767 | 88.31 | 60.92 | 111 | 375 |
| R3_120_mq-wlb-redundant_r3 | 0.224 | 284848 | 640 | 0 | 15834 | 421 | 87.99 | 54.31 | 22 | 409 |
| R4_120_mq-wlb-off_r1 | 30.146 | 284835 | 86039 | 45199 | 112790 | 30647 | 541.93 | 55.37 | 224 | 217 |
| R4_120_mq-wlb-redundant_r1 | 30.044 | 284833 | 85775 | 43071 | 115077 | 31306 | 578.47 | 55.83 | 225 | 219 |
| R4_120_mq-wlb-off_r2 | 28.035 | 284859 | 79480 | 52745 | 105018 | 29402 | 561.27 | 55.07 | 219 | 220 |
| R4_120_mq-wlb-redundant_r2 | 28.342 | 284840 | 80485 | 42573 | 110172 | 32128 | 576.19 | 55.91 | 225 | 220 |
| R4_120_mq-wlb-off_r3 | 20.076 | 284850 | 56751 | 29658 | 86216 | 33924 | 457.75 | 55.93 | 226 | 221 |
| R4_120_mq-wlb-redundant_r3 | 23.146 | 284849 | 65888 | 49377 | 90772 | 28961 | 587.89 | 54.43 | 218 | 221 |

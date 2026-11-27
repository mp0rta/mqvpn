# SRT single-path vs mqvpn multipath — tier 1 results

- date: 2026-10-17 12:11
- kernel: 7.0.0-38-generic
- srt-xtransmit: v0.3.0
- mqvpn: d567e5cc
- duration: 60s/run, scheduler per arm (client), wlb (server), reorder off, lossmaxttl 32, cc bbr2
- suite redundant: send rate 10 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25), duplication on the client only, server scheduler wlb
- rxA/rxB: MB the server received per path during the send (uplink wire bytes, all traffic)
- measured loss [R3]: path A ping x500 (round trip): 500 packets transmitted, 416 received, 16.8% packet loss, time 5832ms

| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) | rxA MB | rxB MB |
|---|---|---|---|---|---|---|---|---|---|---|
| R2_120_mq-wlb-off_r1 | 0.202 | 56971 | 105 | 0 | 4738 | 4854 | 122.35 | 11.15 | 49 | 39 |
| R2_120_mq-wlb-redundant_r1 | 0.004 | 56969 | 2 | 0 | 55557 | 95 | 114.64 | 20.50 | 82 | 81 |
| R2_120_mq-wlb-off_r2 | 0.312 | 56968 | 139 | 0 | 4242 | 4263 | 116.74 | 11.04 | 50 | 38 |
| R2_120_mq-wlb-redundant_r2 | 0.018 | 56970 | 1 | 0 | 55263 | 89 | 113.26 | 20.46 | 82 | 81 |
| R2_120_mq-wlb-off_r3 | 0.269 | 56970 | 162 | 0 | 3788 | 3797 | 117.75 | 10.96 | 55 | 32 |
| R2_120_mq-wlb-redundant_r3 | 0.009 | 56969 | 2 | 0 | 56002 | 104 | 116.74 | 20.55 | 82 | 82 |
| R3_120_mq-wlb-off_r1 | ERR | - | - | - | NA | - | - | - | - | - |
| R3_120_mq-wlb-redundant_r1 | 0.000 | 56969 | 0 | 0 | 43790 | 2456 | 72.64 | 19.99 | 75 | 84 |
| R3_120_mq-wlb-off_r2 | ERR | - | - | - | NA | - | - | - | - | - |
| R3_120_mq-wlb-redundant_r2 | ERR | - | - | - | NA | - | - | - | - | - |
| R3_120_mq-wlb-off_r3 | 3.448 | 56966 | 1974 | 0 | 9209 | 10082 | 81.10 | 11.67 | 41 | 52 |
| R3_120_mq-wlb-redundant_r3 | 0.000 | 56970 | 0 | 0 | 44239 | 2302 | 71.56 | 20.00 | 75 | 84 |
| R4_120_mq-wlb-off_r1 | 1.627 | 56968 | 911 | 0 | 4098 | 4101 | 131.86 | 10.88 | 30 | 56 |
| R4_120_mq-wlb-redundant_r1 | 0.125 | 56965 | 51 | 0 | 41727 | 221 | 126.22 | 17.97 | 61 | 81 |
| R4_120_mq-wlb-off_r2 | 2.208 | 56965 | 1248 | 0 | 4460 | 4473 | 133.51 | 10.88 | 33 | 54 |
| R4_120_mq-wlb-redundant_r2 | 0.137 | 56967 | 59 | 0 | 41016 | 268 | 124.01 | 17.88 | 61 | 81 |
| R4_120_mq-wlb-off_r3 | 1.633 | 56963 | 913 | 0 | 4918 | 4935 | 131.82 | 11.02 | 27 | 60 |
| R4_120_mq-wlb-redundant_r3 | 0.151 | 56970 | 63 | 0 | 40532 | 263 | 126.70 | 17.73 | 60 | 81 |

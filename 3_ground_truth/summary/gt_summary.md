# Derived ground truth Summary

Created: 2026-10-20T13:37:30 

Source: the 819 PCAP files of CIC-DDoS2019, capture day 01-12; re-extracted flows: 50,063,115; CICFlowMeter took 1.98 h for 250,783,287 packets.

Released data: one `gt_flows_<pcap>.parquet` file per PCAP file (819 files, labels per flow). The PCAP files are available from the Canadian Institute for Cybersecurity

## Ground-truth label distribution

| Label | Flows | Share |
|---|---|---|
| TFTP | 19,922,395 | 0.3979 |
| UDP_Reflection_Attack | 12,584,116 | 0.2514 |
| AMBIGUOUS | 7,203,627 | 0.1439 |
| DrDoS_NetBIOS | 3,934,314 | 0.0786 |
| DrDoS_MSSQL | 3,511,306 | 0.0701 |
| Syn | 1,656,049 | 0.0331 |
| DrDoS_NTP | 1,190,940 | 0.0238 |
| BENIGN | 56,863 | 0.0011 |
| UDP-lag | 3,505 | 0.0001 |

## AMBIGUOUS by reason code

| Code | Flows | % of all flows | % of AMBIGUOUS |
|---|---|---|---|
| `behaviour_schedule_conflict` | 7,135,348 | 14.25% | 99.05% |
| `cross_window` | 63,708 | 0.13% | 0.88% |
| `protocol_mismatch` | 2,339 | 0.00% | 0.03% |
| `endpoint_conflict` | 1,471 | 0.00% | 0.02% |
| `webddos_window` | 744 | 0.00% | 0.01% |
| `protocol_mismatch_udplag_tcp` | 17 | 0.00% | 0.00% |

## By official attack window (active schedule; window = flow start)

Ground-truth label:

| window | AMBIGUOUS | BENIGN | DrDoS_MSSQL | DrDoS_NTP | DrDoS_NetBIOS | Syn | TFTP | UDP-lag | UDP_Reflection_Attack |
|---|---|---|---|---|---|---|---|---|---|
| DrDoS_NTP | 1,047 | 1,485 | 0 | 1,190,940 | 0 | 0 | 0 | 0 | 0 |
| DrDoS_DNS | 1,292 | 1,432 | 0 | 0 | 0 | 0 | 0 | 0 | 14,025 |
| DrDoS_LDAP | 975 | 1,575 | 0 | 0 | 0 | 0 | 0 | 0 | 2,068,327 |
| DrDoS_MSSQL | 922 | 1,136 | 3,511,306 | 0 | 0 | 0 | 0 | 0 | 0 |
| DrDoS_NetBIOS | 1,925 | 1,206 | 0 | 0 | 3,934,314 | 0 | 0 | 0 | 0 |
| DrDoS_SNMP | 1,531 | 940 | 0 | 0 | 0 | 0 | 0 | 0 | 4,811,444 |
| DrDoS_SSDP | 918 | 654 | 0 | 0 | 0 | 0 | 0 | 0 | 2,582,697 |
| DrDoS_UDP | 3,529 | 2,401 | 0 | 0 | 0 | 0 | 0 | 0 | 3,107,623 |
| UDP-lag | 352 | 923 | 0 | 0 | 0 | 0 | 0 | 3,505 | 0 |
| WebDDoS | 746 | 1,390 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Syn | 63,952 | 658 | 0 | 0 | 0 | 1,656,049 | 0 | 0 | 0 |
| TFTP | 10,173 | 25,053 | 0 | 0 | 0 | 0 | 19,922,395 | 0 | 0 |
| (outside windows) | 7,116,265 | 18,010 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

AMBIGUOUS by reason:

| window | behaviour_schedule_conflict | cross_window | endpoint_conflict | protocol_mismatch | protocol_mismatch_udplag_tcp | webddos_window |
|---|---|---|---|---|---|---|
| DrDoS_NTP | 1,003 | 7 | 0 | 37 | 0 | 0 |
| DrDoS_DNS | 1,224 | 2 | 0 | 66 | 0 | 0 |
| DrDoS_LDAP | 806 | 2 | 0 | 167 | 0 | 0 |
| DrDoS_MSSQL | 834 | 56 | 0 | 32 | 0 | 0 |
| DrDoS_NetBIOS | 1,011 | 399 | 0 | 515 | 0 | 0 |
| DrDoS_SNMP | 1,122 | 2 | 0 | 407 | 0 | 0 |
| DrDoS_SSDP | 871 | 1 | 0 | 46 | 0 | 0 |
| DrDoS_UDP | 3,266 | 2 | 0 | 261 | 0 | 0 |
| UDP-lag | 329 | 6 | 0 | 0 | 17 | 0 |
| WebDDoS | 0 | 2 | 0 | 0 | 0 | 744 |
| Syn | 773 | 63,179 | 0 | 0 | 0 | 0 |
| TFTP | 9,362 | 3 | 0 | 808 | 0 | 0 |
| (outside windows) | 7,114,747 | 47 | 1,471 | 0 | 0 | 0 |

## BENIGN sub-tags (flows without the attacker endpoint)

By protocol:

| benign_subtag | 0 | 6 | 17 |
|---|---|---|---|
| benign_attack_like | 0 | 2,988 | 0 |
| benign_indeterminate | 358 | 18,120 | 61 |
| benign_like | 1,272 | 12,727 | 21,337 |

Sub-tag × official label:

| benign_subtag | BENIGN | NOT_JOINED |
|---|---|---|
| benign_attack_like | 2,987 | 1 |
| benign_indeterminate | 16,432 | 2,107 |
| benign_like | 34,972 | 364 |

## Behaviour labels

| behaviour | behaviour_rule | n |
|---|---|---|
| attack_like | tcp_syn_no_payload | 2,054,295 |
| attack_like | udp_oneway_flood | 47,924,383 |
| benign_like | lan_multicast_broadcast | 1,543 |
| benign_like | tcp_two_way_payload | 17,363 |
| benign_like | udp_two_way | 21,317 |
| indeterminate | default | 44,214 |

## Agreement with the official CSV labels (descriptive; not used to tune the ground truth)

Ground-truth flows joined to an official CSV row (bidirectional 5-tuple + start time ± 1 s): 0.9999. On joined non-AMBIGUOUS flows, ground-truth label = official label (after class grouping): 0.9916.

By ground-truth class:

| gt_label | n | agree |
|---|---|---|
| BENIGN | 54391.0000 | 1.0000 |
| DrDoS_MSSQL | 3511306.0000 | 1.0000 |
| DrDoS_NTP | 1190940.0000 | 1.0000 |
| DrDoS_NetBIOS | 3934314.0000 | 1.0000 |
| Syn | 1656049.0000 | 0.8086 |
| TFTP | 19922395.0000 | 1.0000 |
| UDP-lag | 3505.0000 | 1.0000 |
| UDP_Reflection_Attack | 12584116.0000 | 0.9966 |

By official window:

| window | n | agree |
|---|---|---|
| DrDoS_NTP | 1192361.0000 | 1.0000 |
| DrDoS_DNS | 15417.0000 | 1.0000 |
| DrDoS_LDAP | 2069833.0000 | 1.0000 |
| DrDoS_MSSQL | 3512402.0000 | 1.0000 |
| DrDoS_NetBIOS | 3935450.0000 | 1.0000 |
| DrDoS_SNMP | 4812365.0000 | 1.0000 |
| DrDoS_SSDP | 2583335.0000 | 1.0000 |
| DrDoS_UDP | 3109935.0000 | 0.9863 |
| UDP-lag | 4394.0000 | 1.0000 |
| WebDDoS | 1327.0000 | 1.0000 |
| Syn | 1656675.0000 | 0.8087 |
| TFTP | 19946333.0000 | 1.0000 |
| (outside windows) | 17189.0000 | 1.0000 |

Ground-truth label (rows) × official label (columns), joined flows:

| gt_label | BENIGN | DrDoS_MSSQL | DrDoS_NTP | DrDoS_NetBIOS | Syn | TFTP | UDP-lag | UDP_Reflection_Attack | WebDDoS |
|---|---|---|---|---|---|---|---|---|---|
| AMBIGUOUS | 0 | 1,011,183 | 11,677 | 158,964 | 243,244 | 160,140 | 3,016 | 5,614,855 | 435 |
| BENIGN | 54,391 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DrDoS_MSSQL | 0 | 3,511,306 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DrDoS_NTP | 0 | 0 | 1,190,940 | 0 | 0 | 0 | 0 | 0 | 0 |
| DrDoS_NetBIOS | 0 | 0 | 0 | 3,934,314 | 0 | 0 | 0 | 0 | 0 |
| Syn | 0 | 0 | 0 | 0 | 1,339,045 | 0 | 317,001 | 0 | 3 |
| TFTP | 0 | 0 | 0 | 0 | 0 | 19,922,395 | 0 | 0 | 0 |
| UDP-lag | 0 | 0 | 0 | 0 | 0 | 0 | 3,505 | 0 | 0 |
| UDP_Reflection_Attack | 0 | 0 | 0 | 0 | 0 | 0 | 42,554 | 12,541,562 | 0 |

Window `DrDoS_NTP`:

| gt_label | BENIGN | DrDoS_NTP |
|---|---|---|
| AMBIGUOUS | 0 | 1,040 |
| BENIGN | 1,421 | 0 |
| DrDoS_NTP | 0 | 1,190,940 |

Window `DrDoS_DNS`:

| gt_label | BENIGN | UDP_Reflection_Attack |
|---|---|---|
| AMBIGUOUS | 0 | 1,284 |
| BENIGN | 1,392 | 0 |
| UDP_Reflection_Attack | 0 | 14,025 |

Window `DrDoS_LDAP`:

| gt_label | BENIGN | UDP_Reflection_Attack |
|---|---|---|
| AMBIGUOUS | 0 | 974 |
| BENIGN | 1,506 | 0 |
| UDP_Reflection_Attack | 0 | 2,068,327 |

Window `DrDoS_MSSQL`:

| gt_label | BENIGN | DrDoS_MSSQL |
|---|---|---|
| AMBIGUOUS | 0 | 919 |
| BENIGN | 1,096 | 0 |
| DrDoS_MSSQL | 0 | 3,511,306 |

Window `DrDoS_NetBIOS`:

| gt_label | BENIGN | DrDoS_NetBIOS |
|---|---|---|
| AMBIGUOUS | 0 | 1,922 |
| BENIGN | 1,136 | 0 |
| DrDoS_NetBIOS | 0 | 3,934,314 |

Window `DrDoS_SNMP`:

| gt_label | BENIGN | UDP_Reflection_Attack |
|---|---|---|
| AMBIGUOUS | 0 | 1,521 |
| BENIGN | 921 | 0 |
| UDP_Reflection_Attack | 0 | 4,811,444 |

Window `DrDoS_SSDP`:

| gt_label | BENIGN | UDP_Reflection_Attack |
|---|---|---|
| AMBIGUOUS | 0 | 916 |
| BENIGN | 638 | 0 |
| UDP_Reflection_Attack | 0 | 2,582,697 |

Window `DrDoS_UDP`:

| gt_label | BENIGN | UDP-lag | UDP_Reflection_Attack | WebDDoS |
|---|---|---|---|---|
| AMBIGUOUS | 0 | 671 | 2,792 | 63 |
| BENIGN | 2,312 | 0 | 0 | 0 |
| UDP_Reflection_Attack | 0 | 42,554 | 3,065,069 | 0 |

Window `UDP-lag`:

| gt_label | BENIGN | UDP-lag | WebDDoS |
|---|---|---|---|
| AMBIGUOUS | 0 | 288 | 64 |
| BENIGN | 889 | 0 | 0 |
| UDP-lag | 0 | 3,505 | 0 |

Window `WebDDoS`:

| gt_label | BENIGN | UDP-lag | WebDDoS |
|---|---|---|---|
| AMBIGUOUS | 0 | 531 | 209 |
| BENIGN | 1,327 | 0 | 0 |

Window `Syn`:

| gt_label | BENIGN | Syn | UDP-lag | WebDDoS |
|---|---|---|---|---|
| AMBIGUOUS | 0 | 63,854 | 71 | 27 |
| BENIGN | 626 | 0 | 0 | 0 |
| Syn | 0 | 1,339,045 | 317,001 | 3 |

Window `TFTP`:

| gt_label | BENIGN | TFTP |
|---|---|---|
| AMBIGUOUS | 0 | 10,141 |
| BENIGN | 23,938 | 0 |
| TFTP | 0 | 19,922,395 |

Window `(outside windows)`:

| gt_label | BENIGN | DrDoS_MSSQL | DrDoS_NTP | DrDoS_NetBIOS | Syn | TFTP | UDP-lag | UDP_Reflection_Attack | WebDDoS |
|---|---|---|---|---|---|---|---|---|---|
| AMBIGUOUS | 0 | 1,010,264 | 10,637 | 157,042 | 179,390 | 149,999 | 1,455 | 5,607,368 | 72 |
| BENIGN | 17,189 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## UDP-lag sensitivity (column `gt_label_udplag`)

| gt_label | AMBIGUOUS | BENIGN | DrDoS_MSSQL | DrDoS_NTP | DrDoS_NetBIOS | Syn | TFTP | UDP-lag | UDP_Reflection_Attack |
|---|---|---|---|---|---|---|---|---|---|
| AMBIGUOUS | 7,203,522 | 0 | 0 | 0 | 0 | 0 | 0 | 105 | 0 |
| BENIGN | 0 | 56,863 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| DrDoS_MSSQL | 0 | 0 | 3,511,306 | 0 | 0 | 0 | 0 | 0 | 0 |
| DrDoS_NTP | 0 | 0 | 0 | 1,190,940 | 0 | 0 | 0 | 0 | 0 |
| DrDoS_NetBIOS | 0 | 0 | 0 | 0 | 3,934,314 | 0 | 0 | 0 | 0 |
| Syn | 0 | 0 | 0 | 0 | 0 | 1,656,049 | 0 | 0 | 0 |
| TFTP | 0 | 0 | 0 | 0 | 0 | 0 | 19,922,395 | 0 | 0 |
| UDP-lag | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3,505 | 0 |
| UDP_Reflection_Attack | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 12,584,116 |

## Chain: ground-truth flow → official CSV row → row_id of seed 1011

| gt_label | n | joined | in_pool |
|---|---|---|---|
| AMBIGUOUS | 7203627.0000 | 1.0000 | 0.0213 |
| BENIGN | 56863.0000 | 0.9565 | 0.9493 |
| DrDoS_MSSQL | 3511306.0000 | 1.0000 | 0.0215 |
| DrDoS_NTP | 1190940.0000 | 1.0000 | 0.0827 |
| DrDoS_NetBIOS | 3934314.0000 | 1.0000 | 0.0236 |
| Syn | 1656049.0000 | 1.0000 | 0.0906 |
| TFTP | 19922395.0000 | 1.0000 | 0.0048 |
| UDP-lag | 3505.0000 | 1.0000 | 0.2571 |
| UDP_Reflection_Attack | 12584116.0000 | 1.0000 | 0.0311 |

Folds of the seed-1011 pool for BENIGN ground-truth flows mapped to a row_id: {0: 10826, 1: 10782, 2: 10793, 3: 10779, 4: 10801}

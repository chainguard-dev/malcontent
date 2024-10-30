rule proc_net_dev: medium {
  meta:
    description                          = "network device statistics"
    hash_2024_Downloads_036a             = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2023_Downloads_d920             = "d920dec25946a86aeaffd5a53ce8c3f05c9a7bac44d5c71481f497de430cb67e"
    hash_2023_Linux_Malware_Samples_1020 = "1020ce1f18a2721b873152fd9f76503dcba5af7b0dd26d80fdb11efaf4878b1a"

  strings:
    $val = "/proc/net/dev"

  condition:
    any of them
}

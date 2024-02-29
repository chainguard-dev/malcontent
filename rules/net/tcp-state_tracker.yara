rule network_state_strings : notable {
  meta:
    hash_2022_trojan_Winnti = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"
    hash_2020_BirdMiner_arachnoidal = "904ad9bc506a09be0bb83079c07e9a93c99ba5d42ac89d444374d80efd7d8c11"
    hash_2021_Mettle = "1020ce1f18a2721b873152fd9f76503dcba5af7b0dd26d80fdb11efaf4878b1a"
    hash_2020_trojan_Meterpreter_Mettle_eukch = "24f3ac76dcd4b0830a1ebd82cc9b1abe98450b8df29cb4f18f032f1077d24404"
    hash_2020_trojan_Meterpreter_Metasploit_uzzxo = "444d8f5a716e89b5944f9d605e490c6845d4af369b024dd751111a6f13bca00d"
    hash_2020_CoinMiner_nbtoz = "741af7d54a95dd3b4497c73001e7b2ba1f607d19d63068b611505f9ce14c7776"
    hash_2020_trojan_Mettle_spuir = "c058aa5d69ce54c42ddd57bd212648fb62ef7325b371bf7198001e1f8bdf3c16"
    hash_2020_trojan_miner_cucnl = "ee0e8516bfc431cb103f16117b9426c79263e279dc46bece5d4b96ddac9a5e90"
  strings:
    $s_ip_frag = "IP_FRAG"
    $s_icmp = "ICMP"
    $s_listen = "LISTEN"
    $s_syn_sent = "SYN_SENT"
    $s_syn_rcvd = "SYN_RCVD"
    $s_established = "ESTABLISHED"
    $s_close_wait = "CLOSE_WAIT"
    $s_closing = "CLOSING"
    $s_fin_wait = "FIN_WAIT"
    $s_time_wait = "TIME_WAIT"
    $s_ack = "ACK"
    $not_pfctl = "pfctl"
    $not_skywark = "kern.skywalk."
    $not_apple = "com.apple.network"
    $not_network_addr = "network address"
    $not_osquery = "OSQUERY_WORKER"
    $not_compdef = "#compdef"
  condition:
    6 of ($s_*) and none of ($not_*)
}

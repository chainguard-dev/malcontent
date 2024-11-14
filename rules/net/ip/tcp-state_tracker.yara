rule network_state_strings: medium {
  meta:
    hash_2023_Downloads_2f13 = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"
    hash_2024_Downloads_e241 = "e241a3808e1f8c4811759e1761e2fb31ce46ad1e412d65bb1ad9e697432bd4bd"

  strings:
    $s_ip_frag        = "IP_FRAG"
    $s_icmp           = "ICMP"
    $s_listen         = "LISTEN"
    $s_syn_sent       = "SYN_SENT"
    $s_syn_rcvd       = "SYN_RCVD"
    $s_established    = "ESTABLISHED"
    $s_close_wait     = "CLOSE_WAIT"
    $s_closing        = "CLOSING"
    $s_fin_wait       = "FIN_WAIT"
    $s_time_wait      = "TIME_WAIT"
    $s_ack            = "ACK"
    $not_pfctl        = "pfctl"
    $not_skywark      = "kern.skywalk."
    $not_apple        = "com.apple.network"
    $not_network_addr = "network address"
    $not_osquery      = "OSQUERY_WORKER"
    $not_compdef      = "#compdef"

  condition:
    6 of ($s_*) and none of ($not_*)
}

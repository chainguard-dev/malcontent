rule network_state_strings: medium {
  meta:
    description = "tracks network connection state"

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

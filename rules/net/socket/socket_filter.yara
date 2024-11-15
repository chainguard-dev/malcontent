rule linux_network_filter: medium {
  meta:
    description = "listens for packets without a socket"

  strings:
    $0x     = "=0x"
    $p_tcp  = "tcp["
    $p_udp  = "udp["
    $p_icmp = "icmp["

  condition:
    $0x and any of ($p*)
}

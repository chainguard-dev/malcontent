rule linux_network_filter_exec: high {
  meta:
    description = "listens for packets without a socket, executes programs"

  strings:
    $0x              = "=0x"
    $p_tcp           = "tcp["
    $p_udp           = "udp["
    $p_icmp          = "icmp["
    $execl           = "execl" fullword
    $execve          = "execve" fullword
    $e_bin_sh        = "/bin/sh"
    $e_bin_bash      = "/bin/bash"
    $not_cilium_node = "CILIUM_SOCK"
    $not_tcp_ipv6    = "tcp[ipv6]"
    $not_keycode     = "keycode=0x"

  condition:
    $0x and any of ($p*) and any of ($e*) and none of ($not*)
}

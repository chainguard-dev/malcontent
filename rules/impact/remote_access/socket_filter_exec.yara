rule linux_network_filter_exec: high {
  meta:
    description = "listens for packets without a socket, executes programs"

  strings:
    $0x = "=0x"

    // Require a real BPF index -- a byte offset ("udp[8:2]=0x7255",
    // "tcp[((tcp[12]&0xf0)>>2):2]") or one of tcpdump's named header fields. A
    // bare "tcp[" also matched x11vnc's "connect_tcp[ipv6]" log prefix, which is
    // what the "tcp[ipv6]" and "keycode=0x" exclusions were papering over.
    $p_tcp  = /\btcp\[([\d\(]|tcpflags\])/
    $p_udp  = /\budp\[[\d\(]/
    $p_icmp = /\bicmp\[([\d\(]|icmp(type|code)\])/

    $execl      = "execl" fullword
    $execve     = "execve" fullword
    $e_bin_sh   = "/bin/sh"
    $e_bin_bash = "/bin/bash"

    $not_cilium_node = "CILIUM_SOCK"

  condition:
    $0x and any of ($p*) and any of ($e*) and none of ($not*)
}

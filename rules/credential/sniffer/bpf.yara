rule sniffer_bpf: medium {
  meta:
    capability  = "CAP_SYS_BPF"
    description = "BPF (Berkeley Packet Filter)"

  strings:
    $ref2 = "/dev/bpf"
    $ref3 = "SetBPF" fullword
    $ref4 = "SetsockoptSockFprog"

  condition:
    any of them
}

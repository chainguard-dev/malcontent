rule bpf: medium {
  meta:
    capability  = "CAP_SYS_BPF"
    description = "BPF (Berkeley Packet Filter)"

  strings:
    $ref  = "bpf" fullword
    $ref2 = "/dev/bpf"
    $ref3 = "SetBPF" fullword
    $ref4 = "SetsockoptSockFprog"

  condition:
    any of them
}

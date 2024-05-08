
rule bpf : medium {
  meta:
    capability = "CAP_SYS_BPF"
    description = "BPF (Berkeley Packet Filter)"
    hash_2023_Downloads_21ca = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"
    hash_2024_Downloads_3105 = "31054fb826b57c362cc0f0dbc8af15b22c029c6b9abeeee9ba8d752f3ee17d7d"
    hash_2024_Downloads_384e = "384ec732200ab95c94c202f42b51e870f51735768888aaabc4e370de74e825e3"
  strings:
    $ref = "bpf" fullword
    $ref2 = "/dev/bpf"
    $ref3 = "SetBPF" fullword
    $ref4 = "SetsockoptSockFprog"
  condition:
    any of them
}

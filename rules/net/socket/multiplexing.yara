rule go_nps_mux: high {
  meta:
    description = "Uses github.com/smallbutstrong/nps-mux to multiplex network connections"
    filetypes   = "elf,go,macho"

  strings:
    $ref1 = ").ReturnBucket"
    $ref2 = ").NewTrafficControl"
    $ref3 = ").SetReadDeadline"

  condition:
    all of them
}

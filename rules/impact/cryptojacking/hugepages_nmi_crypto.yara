rule hugepages_probably_miner: high {
  meta:
    hash_2023_Downloads_9929 = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"

  strings:
    $hugepages  = "vm.nr_hugepages"
    $s_watchdog = "kernel.nmi_watchdog"
    $s_wallet   = "wallet"
    $s_xmr      = "xmr"

  condition:
    $hugepages and any of ($s*)
}

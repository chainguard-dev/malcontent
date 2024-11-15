rule hugepages_probably_miner: high {
  meta:
    description = "modifies memory configuration, likely miner"

  strings:
    $hugepages  = "vm.nr_hugepages"
    $s_watchdog = "kernel.nmi_watchdog"
    $s_wallet   = "wallet"
    $s_xmr      = "xmr"

  condition:
    $hugepages and any of ($s*)
}

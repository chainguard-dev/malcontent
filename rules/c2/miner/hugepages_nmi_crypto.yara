
rule hugepages_probably_miner : high {
  meta:
    hash_2023_Downloads_9929 = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
    hash_2023_Linux_Malware_Samples_1b1a = "1b1a56aec5b02355b90f911cdd27a35d099690fcbeb0e0622eaea831d64014d3"
    hash_2023_Linux_Malware_Samples_1f1b = "1f1bf32f553b925963485d8bb8cc3f0344720f9e67100d610d9e3f5f6bc002a1"
  strings:
    $hugepages = "vm.nr_hugepages"
    $s_watchdog = "kernel.nmi_watchdog"
    $s_wallet = "wallet"
    $s_xmr = "xmr"
  condition:
    $hugepages and any of ($s*)
}

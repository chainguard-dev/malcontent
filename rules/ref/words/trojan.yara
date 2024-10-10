rule trojan_ref : medium {
  meta:
    description = "References a Trojan"
    hash_2023_Linux_Malware_Samples_0afd = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"
    hash_2023_Linux_Malware_Samples_206a = "206ad8fec64661c1fed8f20f71523466d0ca4ed9c01d20bea128bfe317f4395a"
    hash_2023_Linux_Malware_Samples_341a = "341a49940749d5f07d32d1c8dfddf6388a11e45244cc54bc8768a8cd7f00b46a"
  strings:
    $s_trojan = "trojan" fullword
    $s_Trojan = "Trojan"
  condition:
    any of ($s*)
}

rule trojan_ref_leet : high {
  meta:
    description = "References a Trojan"
    hash_2023_Linux_Malware_Samples_0afd = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"
    hash_2023_Linux_Malware_Samples_206a = "206ad8fec64661c1fed8f20f71523466d0ca4ed9c01d20bea128bfe317f4395a"
    hash_2023_Linux_Malware_Samples_341a = "341a49940749d5f07d32d1c8dfddf6388a11e45244cc54bc8768a8cd7f00b46a"
  strings:
    $s_tr0jan = "tr0jan" fullword
  condition:
    any of ($s*)
}

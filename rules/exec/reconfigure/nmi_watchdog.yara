rule nmi_watchdog: medium {
  meta:
    description                       = "accesses kern.nmi_watchdog control"
    hash_2023_Txt_Malware_Sustes_0e77 = "0e77291955664d2c25d5bfe617cec12a388e5389f82dee5ae4fd5c5d1f1bdefe"

  strings:
    $ref = "nmi_watchdog"

  condition:
    $ref
}

rule nmi_watchdog_disable: high {
  meta:
    description                       = "disables kern.nmi_watchdog - possible miner"
    hash_2023_Txt_Malware_Sustes_0e77 = "0e77291955664d2c25d5bfe617cec12a388e5389f82dee5ae4fd5c5d1f1bdefe"

  strings:
    $ref = "nmi_watchdog=0"

  condition:
    any of them
}

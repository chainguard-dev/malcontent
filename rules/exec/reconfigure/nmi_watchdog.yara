rule nmi_watchdog: medium {
  meta:
    description = "accesses kern.nmi_watchdog control"

  strings:
    $ref = "nmi_watchdog"

  condition:
    $ref
}

rule nmi_watchdog_disable: high {
  meta:
    description = "disables kern.nmi_watchdog - possible miner"

  strings:
    $ref = "nmi_watchdog=0"

  condition:
    any of them
}

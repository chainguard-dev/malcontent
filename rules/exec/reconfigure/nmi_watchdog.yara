rule nmi_watchdog: medium {
  meta:
    description                          = "accesses kern.nmi_watchdog control"
    hash_2023_Txt_Malware_Sustes_0e77    = "0e77291955664d2c25d5bfe617cec12a388e5389f82dee5ae4fd5c5d1f1bdefe"
    hash_2023_Unix_Downloader_Rocke_228e = "228ec858509a928b21e88d582cb5cfaabc03f72d30f2179ef6fb232b6abdce97"
    hash_2023_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"

  strings:
    $ref = "nmi_watchdog"

  condition:
    $ref
}

rule nmi_watchdog_disable: high {
  meta:
    description                          = "disables kern.nmi_watchdog - possible miner"
    hash_2023_Txt_Malware_Sustes_0e77    = "0e77291955664d2c25d5bfe617cec12a388e5389f82dee5ae4fd5c5d1f1bdefe"
    hash_2023_Unix_Downloader_Rocke_228e = "228ec858509a928b21e88d582cb5cfaabc03f72d30f2179ef6fb232b6abdce97"
    hash_2023_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"

  strings:
    $ref = "nmi_watchdog=0"

  condition:
    any of them
}


rule nps_tunnel : critical {
  meta:
    description = "Uses NPS, a intranet penetration proxy server"
    hash_2024_Downloads_384e = "384ec732200ab95c94c202f42b51e870f51735768888aaabc4e370de74e825e3"
  strings:
    $ref1 = ".LoadTaskFromJsonFile"
    $ref2 = ".LoadHostFromJsonFile"
  condition:
    all of them
}

rule nps_tunnel: critical {
  meta:
    description = "Uses NPS, a intranet penetration proxy server"

  strings:
    $ref1 = ".LoadTaskFromJsonFile"
    $ref2 = ".LoadHostFromJsonFile"

  condition:
    all of them
}

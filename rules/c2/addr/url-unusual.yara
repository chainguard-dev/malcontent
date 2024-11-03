rule unusual_nodename: medium {
  meta:
    description = "Contains HTTP hostname with a long node name"

  strings:
    $ref = /https*:\/\/\w{16,}\//

  condition:
    filesize < 5MB and $ref
}

rule exotic_tld: high {
  meta:
    description = "Contains HTTP hostname with unusual top-level domain"

  strings:
    $http_exotic_tld = /https*:\/\/[\w\-\.]{1,128}\.(vip|red|cc|wtf|top|pw|ke|space|zw|bd|ke|am|sbs|date|pw|quest|cd|bid|xyz|cm|xxx|casino|online|poker)\//
    $not_electron    = "ELECTRON_RUN_AS_NODE"
    $not_nips        = "nips.cc"
    $not_gov_bd      = ".gov.bd"
    $not_eol         = "endoflife.date"

  condition:
    filesize < 10MB and any of ($http*) and none of ($not_*)
}

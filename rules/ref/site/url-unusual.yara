
rule unusual_nodename {
  meta:
    description = "Contains HTTP hostname with a long node name"
  strings:
    $ref = /https*:\/\/\w{16,}\//
  condition:
    $ref
}

rule exotic_tld {
  meta:
    description = "Contains HTTP hostname with unusual top-level domain"
  strings:
    $http_exotic_tld = /https*:\/\/[\w\-\.]{1,128}\.(vip|red|cc|wtf|top|pw|ke|space|zw|bd|ke|am|sbs|date|pw|quest|cd|bid|xyz|cm|xxx|casino|online|poker)\//
    $not_electron = "ELECTRON_RUN_AS_NODE"
    $not_nips = "nips.cc"
    $not_gov_bd = ".gov.bd"
  condition:
    any of ($http*) and none of ($not_*)
}

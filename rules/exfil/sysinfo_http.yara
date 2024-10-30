rule sysinfo_http_hostname: medium {
  meta:
    description                       = "sends host information via HTTP GET variables"
    hash_2023_Unix_Trojan_Redxor_0a76 = "0a76c55fa88d4c134012a5136c09fb938b4be88a382f88bf2804043253b0559f"

  strings:
    $ref            = "&hostname="
    $not_dns        = "act=dnsrec.add"
    $not_cloud_init = "Cloud-Init"

  condition:
    $ref and none of ($not*)
}

rule sysinfo_http_uname: high {
  meta:
    description                       = "sends host information via HTTP GET variables"
    hash_2023_Unix_Trojan_Redxor_0a76 = "0a76c55fa88d4c134012a5136c09fb938b4be88a382f88bf2804043253b0559f"

  strings:
    $ref2 = "&uname="

  condition:
    any of them
}

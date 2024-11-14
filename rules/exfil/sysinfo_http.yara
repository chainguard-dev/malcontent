rule sysinfo_http_hostname: medium {
  meta:
    description = "sends host information via HTTP GET variables"

  strings:
    $ref            = "&hostname="
    $not_dns        = "act=dnsrec.add"
    $not_cloud_init = "Cloud-Init"

  condition:
    $ref and none of ($not*)
}

rule sysinfo_http_uname: high {
  meta:
    description = "sends host information via HTTP GET variables"

  strings:
    $ref2 = "&uname="

  condition:
    any of them
}

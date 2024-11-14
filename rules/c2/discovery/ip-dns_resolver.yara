rule google_dns_ip: medium {
  meta:
    description             = "contains Google Public DNS resolver IP"




  strings:
    $primary   = "8.8.8.8"
    $secondary = "8.8.4.4"

  condition:
    any of them
}

rule opendns_ip: medium {
  meta:
    description = "contains OpenDNS DNS resolver IP"



  strings:
    $primary   = "208.67.222.222"
    $secondary = "208.67.220.220"

  condition:
    any of them
}

rule ctrld_ip: high {
  meta:
    description = "contains 'Control D' DNS resolver IP"

  strings:
    $primary   = "76.76.2.0"
    $secondary = "76.76.10.0"

  condition:
    any of them
}

rule quad9_ip: medium {
  meta:
    description          = "contains Quad9 DNS resolver IP"

    hash_2023_OK_ad69    = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"

  strings:
    $primary   = "9.9.9.9"
    $secondary = "149.112.112.112"

  condition:
    any of them
}

rule one_one_four_dns_ip: medium {
  meta:
    description = "contains I14DNS DNS resolver IP"



  strings:
    $d_114dns = "114.114.114.114"

  condition:
    any of them
}

rule ipinfo_dns_ip: high {
  meta:
    description = "contains IPInfo DNS resolver IP"



  strings:
    $ref = "168.95.1.1"

  condition:
    any of them
}

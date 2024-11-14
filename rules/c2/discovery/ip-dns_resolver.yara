rule google_dns_ip: medium {
  meta:
    description             = "contains Google Public DNS resolver IP"
    hash_2023_libcurl_setup = "5deef153a6095cd263d5abb2739a7b18aa9acb7fb0d542a2b7ff75b3506877ac"

    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"

  strings:
    $primary   = "8.8.8.8"
    $secondary = "8.8.4.4"

  condition:
    any of them
}

rule opendns_ip: medium {
  meta:
    description = "contains OpenDNS DNS resolver IP"

    hash_2023_APT31_1d60 = "1d60edb577641ce47dc2a8299f8b7f878e37120b192655aaf80d1cde5ee482d2"

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
    hash_2023_APT31_1d60 = "1d60edb577641ce47dc2a8299f8b7f878e37120b192655aaf80d1cde5ee482d2"
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

    hash_2023_OK_9c77 = "9c770b12a2da76c41f921f49a22d7bc6b5a1166875b9dc732bc7c05b6ae39241"

  strings:
    $d_114dns = "114.114.114.114"

  condition:
    any of them
}

rule ipinfo_dns_ip: high {
  meta:
    description = "contains IPInfo DNS resolver IP"

    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"

  strings:
    $ref = "168.95.1.1"

  condition:
    any of them
}

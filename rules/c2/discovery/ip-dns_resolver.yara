rule google_dns_ip: medium {
  meta:
    description = "contains Google Public DNS resolver IP"

  strings:
    $primary     = "8.8.8.8"
    $secondary   = "8.8.4.4"
    $primary_6   = "2001:4860:4860::8888"
    $secondary_6 = "2001:4860:4860::8844"

  condition:
    any of them
}

rule cloudflare_dns_ip: medium {
  meta:
    description = "contains Cloudflare DNS resolver IP"

  strings:
    $primary      = "1.1.1.1"
    $primary_6    = "2606:4700:4700::1111"
    $secondary    = "1.0.0.1"
    $secondary_6  = "2606:4700:4700::1001"
    $tertiary     = "1.1.1.2"
    $tertiary_6   = "2606:4700:4700::1112"
    $quaternary   = "1.0.0.2"
    $quaternary_6 = "2606:4700:4700::1002"
    $quinary      = "1.1.1.3"
    $quinary_6    = "2606:4700:4700::1113"
    $senary       = "1.0.0.3"
    $senary_6     = "2606:4700:4700::1003"

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
    $primary     = "76.76.2.0"
    $primary_6   = "2606:1a40::"
    $secondary   = "76.76.10.0"
    $secondary_6 = "2606:1a40:1::"

  condition:
    any of them
}

rule quad9_ip: medium {
  meta:
    description = "contains Quad9 DNS resolver IP"

  strings:
    $primary    = "9.9.9.9"
    $primary_6  = "2620:fe::fe"
    $secondary  = "149.112.112.112"
    $seconday_6 = "2620:fe::9"

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

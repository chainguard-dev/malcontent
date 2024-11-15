rule dynamic_dns_user: medium {
  meta:
    description = "uses dynamic DNS service"

  strings:
    $d_dyndns        = "dyndns"
    $d_no_ip         = "no-ip."
    $d_eu_org        = "eu.org"
    $d_chickenkiller = "chickenkiller"
    $d_hopto_org     = "hopto.org"
    $d_ddns_name     = "ddns.name"
    $d_duckdns       = "duckdns"
    $d_dont          = "donttargetme"
    $junk            = "amakawababia"

  condition:
    any of ($d*) and not $junk
}

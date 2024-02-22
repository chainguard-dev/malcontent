rule google_dns_ip : notable {
  strings:
    $d_google_public = "8.8.8.8"
  condition:
    any of them
}

rule opendns_ip : suspicious {
  strings:
    $d_opendns = "208.67.222.222"
  condition:
    any of them
}

rule one_one_four_dns_ip : notable {
  strings:
    $d_114dns = "114.114.114.114"
  condition:
    any of them
}

rule google_dns_ip : notable {
  meta:
	description = "Hardcodes Google Public DNS resolvers"
  strings:
    $d_google_public = "8.8.8.8"
    $d_google_public2 = "8.8.4.4"
  condition:
    any of them
}

rule opendns_ip : suspicious {
  meta:
	description = "Hardcodes OpenDNS resolver"
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

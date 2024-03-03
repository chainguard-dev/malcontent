rule google_dns_ip : notable {
  meta:
	description = "Hardcodes Google Public DNS resolver IP"
  strings:
    $primary = "8.8.8.8"
    $secondary = "8.8.4.4"
  condition:
    any of them
}

rule opendns_ip : suspicious {
  meta:
	description = "Hardcodes 'OpenDNS' DNS resolver IP"
  strings:
    $primary = "208.67.222.222"
    $secondary = "208.67.220.220"
  condition:
    any of them
}

rule ctrld_ip : suspicious {
  meta:
	description = "Hardcodes 'Control D' DNS resolver IP"
  strings:
    $primary = "76.76.2.0"
    $secondary = "76.76.10.0"
  condition:
    any of them
}

rule quad9_ip : suspicious {
  meta:
	description = "Hardcodes 'Quad9' DNS resolver IP"
  strings:
    $primary = "9.9.9.9"
    $secondary = "149.112.112.112"
  condition:
    any of them
}


rule one_one_four_dns_ip : notable {
  meta:
	description = "Hardcodes I14DNS DNS resolver IP"
  strings:
    $d_114dns = "114.114.114.114"
  condition:
    any of them
}

rule ipinfo_dns_ip : suspicious {
  meta:
	description = "Hardcodes IPInfo DNS resolver IP"
  strings:
    $ref = "168.95.1.1"
  condition:
    any of them
}

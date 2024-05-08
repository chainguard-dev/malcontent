
rule google_dns_ip : notable {
  meta:
    description = "contains Google Public DNS resolver IP"
  strings:
    $primary = "8.8.8.8"
    $secondary = "8.8.4.4"
  condition:
    any of them
}

rule opendns_ip : notable {
  meta:
    description = "contains OpenDNS DNS resolver IP"
  strings:
    $primary = "208.67.222.222"
    $secondary = "208.67.220.220"
  condition:
    any of them
}

rule ctrld_ip : suspicious {
  meta:
    description = "contains 'Control D' DNS resolver IP"
  strings:
    $primary = "76.76.2.0"
    $secondary = "76.76.10.0"
  condition:
    any of them
}

rule quad9_ip : notable {
  meta:
    description = "contains Quad9 DNS resolver IP"
  strings:
    $primary = "9.9.9.9"
    $secondary = "149.112.112.112"
  condition:
    any of them
}

rule one_one_four_dns_ip : notable {
  meta:
    description = "contains I14DNS DNS resolver IP"
  strings:
    $d_114dns = "114.114.114.114"
  condition:
    any of them
}

rule ipinfo_dns_ip : suspicious {
  meta:
    description = "contains IPInfo DNS resolver IP"
    hash_2023_Unix_Malware_Setag_2f41 = "2f4163b6a30d738f619513cdcc8ee40056eeef9244455225d629a0fc2c58638a"
    hash_2023_Unix_Malware_Setag_d55c = "d55ca59e33aebd0db6c433edac5c5bca6d1781ca4a35e3afcf086abf2047532b"
  strings:
    $ref = "168.95.1.1"
  condition:
    any of them
}

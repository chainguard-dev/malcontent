rule hardcoded_ip: medium {
  meta:
    description = "hardcoded IP address"

  strings:
    // strict: excludes 255.* and *.0.* *.1.*
    $sus_ipv4           = /((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])\.){3}(25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])/ fullword
    $not_version        = /((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])\.){3}(25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])[\.\-]/
    $not_incr           = "10.11.12.13"
    $not_169            = "169.254.169.254"
    $not_spyder         = "/search/spider"
    $not_ruby           = "210.251.121.214"
    $not_1_2_3_4        = "1.2.3.4"
    $not_root_servers_h = "128.63.2.53"
    $not_root_servers_i = "192.36.148.17"
    $not_send_att       = "3.2.5.7"

  condition:
    filesize < 200MB and 1 of ($sus_ip*) and none of ($not*)
}

private rule ip_elf_or_macho {
  condition:
    uint32(0) == 1179403647 or (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178)
}

rule bin_hardcoded_ip: high {
  meta:
    description = "ELF with hardcoded IP address"
    filetypes   = "elf,macho"

  strings:
    // stricter version of what's above: excludes 255.* and *.0.* *.1.*, and 8.* (likely Google)
    $sus_ipv4              = /((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2345679])\.){3}(25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])/ fullword
    $not_version           = /((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])\.){3}(25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])[\.\-]/
    $not_incr              = "10.11.12.13"
    $not_169               = "169.254.169.254"
    $not_spyder            = "/search/spider"
    $not_ruby              = "210.251.121.214"
    $not_1_2_3_4           = "1.2.3.4"
    $not_root_servers_h    = "128.63.2.53"
    $not_root_servers_i    = "192.36.148.17"
    $not_123456789         = "123.45.67.89"
    $not_10_11_12_13       = "10.11.12.13"
    $not_libebt_among_init = "libebt_among_init"
    $not_send_att          = "3.2.5.7"
    $not_192_168           = "192.168."
    $not_2345              = "23.45.67.89"

  condition:
    filesize < 12MB and ip_elf_or_macho and 1 of ($sus_ip*) and none of ($not*)
}

rule http_hardcoded_ip: high exfil {
  meta:
    description = "hardcoded IP address within a URL"

  strings:
    $ipv4             = /https*:\/\/([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}[:\/\w\-\?\.\=]{0,64}/
    $not_metadata     = "http://169.254.169.254"
    $not_100          = "http://100.100.100"
    $not_11           = "http://11.11.11"
    $not_192          = "http://192.168"
    $not_169          = "http://169.254"
    $not_aria         = "http://210.104.33.10/ARIA/"
    $not_placeholder1 = "placeholder:\"e.g. https://192.168.99.200:443/api\""
    $not_placeholder2 = "placeholder:\"e.g. http://138.68.74.142:7860\""

  condition:
    $ipv4 and none of ($not*)
}

rule hardcoded_ip_port: high {
  meta:
    description = "hardcoded IP:port destination"

  strings:
    $ipv4            = /([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}:\d{2,5}/ fullword
    $not_ssdp        = "239.255.255.250:"
    $not_2181        = "10.101.203.230:2181"
    $not_meta        = "169.254.169.254:"
    $not_vnc         = "10.10.10.10:"
    $not_azure_pgsql = "20.66.25.58:5432"
    $not_wireguard   = "127.212.121.99:999"
    $not_minio       = "172.16.34.31:9000"
    $not_test        = "def test_" fullword
    $not_12          = "12.12.12.12:"
    $not_21          = "21.21.21.21:"
    $not_255         = "255.255.255.255:"
    $not_10_11_12_13 = "10.11.12.13:"

  condition:
    any of ($ip*) and none of ($not*)
}

rule ip_port_mention: medium {
  meta:
    description = "mentions an IP and port"

  strings:
    $camelPort = /[a-z]{0,8}Port/ fullword
    $camelIP   = /[a-z]{0,8}Ip/ fullword
    $underPort = /[a-z]{0,8}_port/ fullword
    $underIP   = /[a-z]{0,8}_ip/ fullword
    $wordPort  = "Port" fullword
    $wordIP    = "IP" fullword

  condition:
    all of ($camel*) or all of ($under*) or all of ($word*)
}

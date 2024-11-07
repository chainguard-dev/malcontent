rule hardcoded_ip: medium {
  meta:
    description              = "hardcoded IP address"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_Downloads_0fa8 = "503fcf8b03f89483c0335c2a7637670c8dea59e21c209ab8e12a6c74f70c7f38"
    hash_2023_Downloads_311c = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"

  strings:
    $ipv4          = /((25[0-5]|(2[0-4]|1\d|[1-9]|)[\d])\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d)/ fullword
    $not_localhost = "127.0.0.1"
    $not_broadcast = "255.255.255.255"
    $not_upnp      = "239.255.255.250"
    $not_incr      = "10.11.12.13"
    $not_169       = "169.254.169.254"
    $not_spyder    = "/search/spider"
    $not_ruby      = "210.251.121.214"
    $not_image     = "7.1.1.38"
    $not_224       = "224.0.0.251"

  condition:
    filesize < 200MB and 1 of ($ip*) and none of ($not*)
}

rule elf_hardcoded_ip: high {
  meta:
    description              = "ELF with hardcoded IP address"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_Downloads_0fa8 = "503fcf8b03f89483c0335c2a7637670c8dea59e21c209ab8e12a6c74f70c7f38"
    hash_2023_Downloads_311c = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"

  strings:
    // stricter version of what's above: excludes 255.* and *.0.* *.1.*
    $sus_ipv4           = /((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])\.){3}(25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])/ fullword
    $not_version        = /((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])\.){3}(25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])[\.\-]/
    $not_incr           = "10.11.12.13"
    $not_169            = "169.254.169.254"
    $not_spyder         = "/search/spider"
    $not_ruby           = "210.251.121.214"
    $not_1_2_3_4        = "1.2.3.4"
    $not_root_servers_h = "128.63.2.53"
    $not_root_servers_i = "192.36.148.17"

  condition:
    filesize < 12MB and uint32(0) == 1179403647 and 1 of ($sus_ip*) and none of ($not*)
}

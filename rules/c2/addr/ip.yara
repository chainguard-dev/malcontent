rule hardcoded_ip: medium {
  meta:
    description              = "hardcoded IP address"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_Downloads_0fa8 = "503fcf8b03f89483c0335c2a7637670c8dea59e21c209ab8e12a6c74f70c7f38"
    hash_2023_Downloads_311c = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"

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

  condition:
    filesize < 200MB and 1 of ($sus_ip*) and none of ($not*)
}

rule elf_hardcoded_ip: high {
  meta:
    description              = "ELF with hardcoded IP address"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_Downloads_0fa8 = "503fcf8b03f89483c0335c2a7637670c8dea59e21c209ab8e12a6c74f70c7f38"
    hash_2023_Downloads_311c = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"

  strings:
    // stricter version of what's above: excludes 255.* and *.0.* *.1.*, and 8.* (likely Google)
    $sus_ipv4           = /((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2345679])\.){3}(25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])/ fullword
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

rule http_hardcoded_ip: high exfil {
  meta:
    description                            = "hardcoded IP address within a URL"
    hash_2023_Merlin_48a7                  = "48a70bd18a23fce3208195f4ad2e92fce78d37eeaa672f83af782656a4b2d07f"
    hash_2023_Multios_Trojan_WellMess_bce8 = "bce8ba5b7e6598c15c5ec258199e148272087fde2cd0690ed9b42ba89f2aacea"
    hash_2023_OK_ad69                      = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"

  strings:
    $ipv4         = /https*:\/\/([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}[:\/\w\-\?\.\=]{0,64}/
    $not_metadata = "http://169.254.169.254"
    $not_100      = "http://100.100.100"
    $not_11       = "http://11.11.11"
    $not_192      = "http://192.168"
    $not_169      = "http://169.254"
    $not_aria     = "http://210.104.33.10/ARIA/"

  condition:
    $ipv4 and none of ($not*)
}

rule hardcoded_ip_port: high {
  meta:
    description                      = "hardcoded IP:port destination"
    hash_2023_Merlin_48a7            = "48a70bd18a23fce3208195f4ad2e92fce78d37eeaa672f83af782656a4b2d07f"
    hash_2023_usr_adxintrin_b        = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"

  strings:
    $ipv4            = /([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}:\d{2,5}/ fullword
    $not_ssdp        = "239.255.255.250:1900"
    $not_2181        = "10.101.203.230:2181"
    $not_meta        = "169.254.169.254:80"
    $not_vnc         = "10.10.10.10:5900"
    $not_azure_pgsql = "20.66.25.58:5432"
    $not_wireguard   = "127.212.121.99:999"
    $not_minio       = "172.16.34.31:9000"
    $not_test        = "def test_" fullword

  condition:
    any of ($ip*) and none of ($not*)
}

rule ip_port_mention: medium {
  meta:
    description                  = "mentions an IP and port"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_wesoori    = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2023_Downloads_016a     = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"

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

rule logfile: override {
  meta:
    description          = "logfile"
    ip_and_port          = "medium"
    http_hardcoded_ip    = "medium"
    exploiter            = "medium"
    http_ip_url_with_exe = "medium"
    filetypes            = "txt,log,json"

  strings:
    $timestamp = "@timestamp"

  condition:
    any of them
}

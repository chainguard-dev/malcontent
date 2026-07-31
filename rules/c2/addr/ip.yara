rule hardcoded_ip: medium {
  meta:
    description = "hardcoded IP address"

  strings:
    // strict: excludes 255.* and *.0.* *.1.*
    $sus_ipv4           = /((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])\.){3}(25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])/ fullword
    $not_version        = /((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])\.){3}(25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[2-9])[\.\-]/
    $not_incr           = "10.11.12.13" fullword
    $not_169            = "169.254.169.254" fullword
    $not_ecs            = "169.254.170.2" fullword
    $not_spyder         = "/search/spider"
    $not_ruby           = "210.251.121.214" fullword
    $not_1_2_3_4        = "1.2.3.4"
    $not_root_servers_h = "128.63.2.53" fullword
    $not_root_servers_i = "192.36.148.17" fullword
    $not_send_att       = "3.2.5.7" fullword

  condition:
    // The known-good addresses are themselves $sus_ipv4 matches, so subtract
    // their occurrence counts instead of switching the rule off: naming one
    // benign address no longer excuses every other address in the file. They
    // carry fullword so each one cancels exactly one $sus_ipv4 match.
    // $not_version describes the whole file and $not_spyder/$not_1_2_3_4 are
    // not $sus_ipv4 matches, so those stay membership tests.
    filesize < 200MB and #sus_ipv4 > #not_incr + #not_169 + #not_ecs + #not_ruby + #not_root_servers_h + #not_root_servers_i + #not_send_att and none of ($not_version, $not_spyder, $not_1_2_3_4)
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
    $not_169               = "169.254.169.254" fullword
    $not_spyder            = "/search/spider"
    $not_ruby              = "210.251.121.214" fullword
    $not_1_2_3_4           = "1.2.3.4"
    $not_root_servers_h    = "128.63.2.53" fullword
    $not_root_servers_i    = "192.36.148.17" fullword
    $not_123456789         = "123.45.67.89" fullword
    $not_10_11_12_13       = "10.11.12.13" fullword
    $not_libebt_among_init = "libebt_among_init"
    $not_send_att          = "3.2.5.7" fullword
    $not_192_168           = "192.168."
    $not_2345              = "23.45.67.89" fullword

  condition:
    // Same shape as hardcoded_ip: the eight complete known-good addresses are
    // $sus_ipv4 matches, so their counts are subtracted one-for-one. The
    // remaining strings are either whole-file signals ($not_version), a
    // truncated address class ($not_192_168) or plain symbol/text that
    // $sus_ipv4 never matches, so they stay membership tests.
    filesize < 12MB and ip_elf_or_macho and #sus_ipv4 > #not_169 + #not_ruby + #not_root_servers_h + #not_root_servers_i + #not_123456789 + #not_10_11_12_13 + #not_send_att + #not_2345 and none of ($not_version, $not_spyder, $not_1_2_3_4, $not_libebt_among_init, $not_192_168)
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
    // Every known-good URL here is itself an instance of the text $ipv4
    // generalises, so naming one of them excused every other hardcoded-IP URL in
    // the file. Counting instead requires an $ipv4 match the accepted URLs do not
    // account for. Each $not begins at most one $ipv4 match, so the sum can only
    // overshoot: the truncated forms ($not_100, $not_11, $not_192, $not_169) can
    // cost a match they never produced, and $not_metadata starts with $not_169 so
    // that address is charged twice. Overshooting leaves the suppression stronger,
    // never weaker.
    #ipv4 > #not_metadata + #not_100 + #not_11 + #not_192 + #not_169 + #not_aria + #not_placeholder1 + #not_placeholder2
}

rule hardcoded_ip_port: high {
  meta:
    description = "hardcoded IP:port destination"

  strings:
    $ipv4            = /([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}:\d{2,5}/ fullword
    $not_ssdp        = "239.255.255.250:"
    $not_2181        = "10.101.203.230:2181" fullword
    $not_meta        = "169.254.169.254:"
    $not_vnc         = "10.10.10.10:"
    $not_azure_pgsql = "20.66.25.58:5432" fullword
    $not_wireguard   = "127.212.121.99:999" fullword
    $not_minio       = "172.16.34.31:9000" fullword
    $not_test        = "def test_" fullword
    $not_12          = "12.12.12.12:"
    $not_21          = "21.21.21.21:"
    $not_255         = "255.255.255.255:"
    $not_10_11_12_13 = "10.11.12.13:"

  condition:
    // The four known-good endpoints include a port, so each is an exact $ipv4
    // match and its count cancels exactly one $ipv4 match. The bare
    // address-and-colon strings stop short of the port $ipv4 requires, so they
    // can match where $ipv4 cannot and have to stay membership tests.
    #ipv4 > #not_2181 + #not_azure_pgsql + #not_wireguard + #not_minio and none of ($not_ssdp, $not_meta, $not_vnc, $not_test, $not_12, $not_21, $not_255, $not_10_11_12_13)
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

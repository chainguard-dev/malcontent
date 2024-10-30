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
    $not_test        = "def test_" fullword

  condition:
    any of ($ip*) and none of ($not*)
}

rule ip_and_port: medium {
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

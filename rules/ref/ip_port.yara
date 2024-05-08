
rule hardcoded_ip_port : high {
  meta:
    description = "hardcoded IP:port destination"
    hash_2023_Merlin_48a7 = "48a70bd18a23fce3208195f4ad2e92fce78d37eeaa672f83af782656a4b2d07f"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
  strings:
    $ipv4 = /([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}:\d{2,5}/ fullword
    $not_ssdp = "239.255.255.250:1900"
    $not_2181 = "10.101.203.230:2181"
    $not_meta = "169.254.169.254:80"
    $not_vnc = "10.10.10.10:5900"
    $not_azure_pgsql = "20.66.25.58:5432"
  condition:
    any of ($ip*) and none of ($not*)
}

rule ip_and_port : notable {
  meta:
    description = "mentions an IP and port"
  strings:
    $camelPort = /[a-z]{0,8}Port/ fullword
    $camelIP = /[a-z]{0,8}Ip/ fullword
    $underPort = /[a-z]{0,8}_port/ fullword
    $underIP = /[a-z]{0,8}_ip/ fullword
    $wordPort = "Port" fullword
    $wordIP = "IP" fullword
  condition:
    all of ($camel*) or all of ($under*) or all of ($word*)
}

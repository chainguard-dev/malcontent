
rule basic_recon : notable {
  meta:
    hash_2023_Downloads_f864 = "f864922f947a6bb7d894245b53795b54b9378c0f7633c521240488e86f60c2c5"
    hash_2023_Linux_Malware_Samples_2c98 = "2c98b196a51f737f29689d16abeea620b0acfa6380bdc8e94a7a927477d81e3a"
    hash_2023_Linux_Malware_Samples_3292 = "329255e33f43e6e9ae5d5efd6f5c5745c35a30d42fb5099beb51a6e40fe9bd76"
  strings:
    $c_whoami = "whoami" fullword
    $c_id = "id" fullword
    $c_hostname = "hostname" fullword
    $c_uname = "uname -a"
    $c_ip_addr = "ip addr" fullword
    $not_usage = "Usage: inet"
    $not_apple_smb = "com.apple.smbd"
    $not_bashopts = "BASHOPTS"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_license = "For license information please see"
  condition:
    filesize < 26214400 and 3 of ($c*) and none of ($not*)
}

rule invasive_recon_val : notable {
  meta:
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_Downloads_3105 = "31054fb826b57c362cc0f0dbc8af15b22c029c6b9abeeee9ba8d752f3ee17d7d"
  strings:
    $c_ifconfig = /ifconfig.{0,4}-a/ fullword
    $c_lspi = "lspci"
    $c_ufw = /ufw.{0,4}status/
    $c_sudo = /sudo.{0,4}-l/
    $c_ip_route = /ip.{0,4}route/
    $c_netstat = /netstat.{0,4}-a/
    $c_ip_addr = /ip.{0,4}addr/ fullword
    $not_usage = "Usage: inet"
    $not_apple_smb = "com.apple.smbd"
    $not_bashopts = "BASHOPTS"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_license = "For license information please see"
  condition:
    filesize < 26214400 and any of ($c*) and none of ($not*)
}

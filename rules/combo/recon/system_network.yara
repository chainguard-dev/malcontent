rule recon_commands : suspicious {
  meta:
    hash_2020_trojan_webshell_quwmldl_rfxn = "f1375cf097b3f28247762147f8ee3755e0ce26e24fbf8a785fe4e5b42c1fed05"
    hash_2017_Perl_FruitFly_afpscan = "bbbf73741078d1e74ab7281189b13f13b50308cf03d3df34bc9f6a90065a4a55"
    hash_2021_ANDR_miner_eomap = "329255e33f43e6e9ae5d5efd6f5c5745c35a30d42fb5099beb51a6e40fe9bd76"
    hash_2021_ADR_CoinMiner_nutar = "fb6b327104eb37d42f83b552430ef9b1e45ee49c737d562876650d75e3a88e57"
    hash_2023_Sodinokibi = "f864922f947a6bb7d894245b53795b54b9378c0f7633c521240488e86f60c2c5"
    hash_2023_Linux_Malware_Samples_2c98 = "2c98b196a51f737f29689d16abeea620b0acfa6380bdc8e94a7a927477d81e3a"
    hash_2023_Linux_Malware_Samples_3ffc = "3ffc2327a5dd17978f62c44807e5bf9904bcdef222012a11e48801faf6861a67"
    hash_2023_Linux_Malware_Samples_564a = "564a666d0a7efc39c9d53f5c6c4d95d5f7f6b7bff2dc9aa3c871f8c49650a99b"
  strings:
    $c_whoami = "whoami" fullword
    $c_id = "id" fullword
    $c_hostname = "hostname" fullword
    $c_ifconfig = "ifconfig" fullword
    $c_uname = "uname -a"
    $c_lspi = "lspci"
	$c_ufw = "ufw status"
	$c_sudo = "sudo -l"
	$c_ip_route = "ip route"
	$c_netstat = "netstat -a"
	$c_ip_addr = "ip addr" fullword
    $not_usage = "Usage: inet"
    $not_apple_smb = "com.apple.smbd"
    $not_bashopts = "BASHOPTS"
    $not_private = "/System/Library/PrivateFrameworks/"
	$not_license = "For license information please see"
  condition:
    filesize < 26214400 and 3 of ($c*) and none of ($not*)
}

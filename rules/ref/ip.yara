
rule hardcoded_ip : notable {
  meta:
    description = "hardcoded IP address"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_Downloads_0fa8a2e98ba17799d559464ab70cce2432f0adae550924e83d3a5a18fe1a9fc8 = "503fcf8b03f89483c0335c2a7637670c8dea59e21c209ab8e12a6c74f70c7f38"
    hash_2023_Downloads_311c = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"
  strings:
    $ipv4 = /([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}/ fullword
    $not_localhost = "127.0.0.1"
    $not_broadcast = "255.255.255.255"
    $not_upnp = "239.255.255.250"
    $not_weirdo = "635.100.12.38"
    $not_incr = "10.11.12.13"
    $not_169 = "169.254.169.254"
    $not_spyder = "/search/spider"
    $not_ruby = "210.251.121.214"
  condition:
    1 of ($ip*) and none of ($not*)
}

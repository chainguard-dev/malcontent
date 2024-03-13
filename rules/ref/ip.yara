rule hardcoded_ip : notable {
  meta:
	description = "hardcoded IP address"
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

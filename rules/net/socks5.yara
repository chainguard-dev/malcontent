
rule socks5 : notable {
	meta:
		description = "Supports SOCK5 proxies"
	strings:
		$ref = ".Socks5"
		$ref2 = "SOCKS5"
	    $rp_connect = "CONNECT %s"
		$rp_socksproxy = "socksproxy"
		$rp_socks_proxy = "socks proxy"
		$rp_socksv5 = "SOCKSv5"
		$rp_socks_percent = "SOCKS %"
		$rp_socks5 = "socks5" fullword
		$rgo_socks5 = "go-socks5"

		$not_etc_services = "Registered Ports are not controlled by the IANA"
	condition:
		any of ($r*) and none of ($not*)
}
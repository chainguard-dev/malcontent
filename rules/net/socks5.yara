
rule socks5 : notable {
	meta:
		description = "Supports SOCK5 proxies"
	strings:
		$ref = ".Socks5"
		$ref2 = "SOCKS5"
	    $p_connect = "CONNECT %s"
		$p_socksproxy = "socksproxy"
		$p_socks_proxy = "socks proxy"
		$p_socksv5 = "SOCKSv5"
		$p_socks_percent = "SOCKS %"
		$p_socks5 = "socks5" fullword
		$go_socks5 = "go-socks5"
	condition:
		any of them
}
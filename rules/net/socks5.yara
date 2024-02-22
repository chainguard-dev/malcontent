
rule socks5 : notable {
	meta:
		description = "Supports SOCK5 proxies"
	strings:
		$ref = ".Socks5"
		$ref2 = "SOCKS5"
	condition:
		any of them
}
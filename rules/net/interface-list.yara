rule bsd_ifaddrs {
	meta:
		description = "list network interfaces and their associated addresses"
	strings:
		$getifaddrs = "getifaddrs" fullword
		$freeifaddrs = "freeifaddrs" fullword
		$ifconfig = "ifconfig" fullword
	condition:
		any of them
}

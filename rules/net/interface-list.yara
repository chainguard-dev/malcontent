rule bsd_ifaddrs : notable {
	meta:
		description = "list network interfaces and their associated addresses"
	strings:
		$getifaddrs = "getifaddrs" fullword
		$freeifaddrs = "freeifaddrs" fullword
		$ifconfig = "ifconfig" fullword
		$proc = "/proc/net/dev"
	condition:
		any of them
}

rule bsd_ifaddrs : notable {
	meta:
		description = "list network interfaces"
	strings:
		$getifaddrs = "getifaddrs" fullword
		$freeifaddrs = "freeifaddrs" fullword
		$ifconfig = "ifconfig" fullword
		$proc = "/proc/net/dev"
	condition:
		any of them
}


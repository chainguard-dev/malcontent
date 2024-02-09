rule bsd_ifaddrs {
	strings:
		$getifaddrs = "getifaddrs" fullword
		$freeifaddrs = "freeifaddrs" fullword
	condition:
		any of them
}

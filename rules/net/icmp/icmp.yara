rule icmp {
	strings:
		$ICMP = "ICMP" fullword
		$icmp = "icmp" fullword
	condition:
		any of them
}
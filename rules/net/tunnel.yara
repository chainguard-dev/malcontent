rule tunnel : notable {
	meta:
		description = "Creates a network tunnel"
		syscall = "setsockopt"
	strings:
		$tunnel = "tunnel" fullword
		$inet = "inet_addr" fullword
	condition:
		all of them
}

rule tunnel2 : notable {
	meta:
		description = "Creates a network tunnel"
		syscall = "setsockopt"
	strings:
		$Tunnel = "Tunnel"
		$inet = "inet_addr" fullword
	condition:
		all of them
}
rule tunnel : suspicious {
	meta:
		description = "Creates a network tunnel"
		syscall = "setsockopt"
	strings:
		$subnet = "tunnel" fullword
		$inet = "inet_addr" fullword
	condition:
		all of them
}
rule setsockopt : harmless {
	meta:
		description = "set socket options"
		syscall = "setsockopt"
	strings:
		$setsockopt = "setsockopt" fullword
	condition:
		any of them
}
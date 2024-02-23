rule setsockopt : harmless {
	meta:
		description = "set socket options"
		syscall = "setsockopt"
	strings:
		$setsockopt = "setsockopt" fullword
		$Setsockopt = "Setsockopt" fullword
	condition:
		any of them
}
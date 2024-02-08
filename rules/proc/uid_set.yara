rule setuid {
	meta:
		description = "Uses setuid() to change users"
		syscall = "setuid"
		// pledge = "rpath"
	strings:
		$setuid_fx = "setuid()" fullword
	condition:
		any of them
}
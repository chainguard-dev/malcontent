rule syscalls : harmless {
	meta:
		pledge = "proc"
		syscall = "setsid"
	strings:
		$setsid = "setsid" fullword
	condition:
		any of them
}


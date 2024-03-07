rule kill : harmless {
	meta:
		syscall = "kill"
		pledge = "proc"
	strings:
		$kill = "_kill" fullword
		$go = "syscall.Kill" fullword
	condition:
		any of them
}
rule kill : harmless {
	meta:
		syscall = "kill"
		pledge = "proc"
	strings:
		$kill = "_kill" fullword
	condition:
		any of them
}
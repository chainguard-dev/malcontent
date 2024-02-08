rule kill {
	meta:
		syscall = "kill"
		pledge = "proc"
	strings:
		$kill = "_kill" fullword
	condition:
		any of them
}
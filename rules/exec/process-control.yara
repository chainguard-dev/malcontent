rule prctl : harmless {
	meta:
		syscall = "prctl"
	strings:
		$prctl = "prctl" fullword
	condition:
		any of them
}
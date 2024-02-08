rule getpid : harmless {
	meta:
		syscall = "getpid"
	strings:
		$ref = "getpid" fullword
		$Getpid = "Getpid" fullword
	condition:
		any of them
}
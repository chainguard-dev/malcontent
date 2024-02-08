rule getuid : harmless {
	meta:
		syscall = "getuid"
	strings:
		$getuid = "getuid" fullword
		$Getuid = "Getuid" fullword
	condition:
		any of them
}
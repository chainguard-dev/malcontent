rule getuid {
	meta:
		syscall = "getuid"
	strings:
		$getuid = "getuid" fullword
	condition:
		any of them
}
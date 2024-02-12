rule getegid {
	meta:
		syscall = "getegid"
		description = "returns the effective group id of the current process"
	strings:
		$getuid = "getegid" fullword
		$Getuid = "Getegid" fullword
	condition:
		any of them
}
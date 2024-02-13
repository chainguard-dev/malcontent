rule whoami : suspicious {
	meta:
		syscall = "getuid"
		description = "returns the user name running this process"
	strings:
		$ref = "whoami" fullword
	condition:
		any of them
}
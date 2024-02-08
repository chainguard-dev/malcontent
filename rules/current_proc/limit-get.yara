rule getrlimit : harmless {
	meta:
		syscall = "getrlimit"
		description = " control maximum system resource consumption"
		pledge = "id"
	strings:
		$ref = "getrlimit" fullword
		$go = "Getrlimit" fullword
	condition:
		any of them
}
rule getrlimit : harmless {
	meta:
		syscall = "getrlimit"
		description = " control maximum system resource consumption"
		pledge = "id"
	strings:
		$ref = "getrlimit" fullword
	condition:
		any of them
}
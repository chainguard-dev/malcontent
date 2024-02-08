rule setrlimit : harmless {
	meta:
		syscall = "setrlimit"
		description = " control maximum system resource consumption"
		pledge = "id"
	strings:
		$ref = "setrlimit" fullword
	condition:
		any of them
}
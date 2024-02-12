rule fd_write : harmless {
	meta:
		description = "Writes to file descriptors"
		pledge = "stdio"
		syscall = "pwrite64"
	strings:
		$ref = "pwrited" fullword
		$ref2 = "pwrite" fullword
		$ref3 = "pwrite64" fullword
	condition:
		any of them
}

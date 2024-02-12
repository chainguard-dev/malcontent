rule fd_read : harmless {
	meta:
		description = "Reads from file descriptors"
		pledge = "stdio"
		syscall = "pread64"
	strings:
		$ref = "pread" fullword
	condition:
		any of them
}

rule fd_read : harmless {
	meta:
		description = "Reads from file descriptors"
		pledge = "stdio"
	strings:
		$ref = "pread" fullword
	condition:
		any of them
}

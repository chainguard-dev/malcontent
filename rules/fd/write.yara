rule fd_write : harmless {
	meta:
		description = "Writes to file descriptors"
		pledge = "stdio"
	strings:
		$ref = "pwrited" fullword
	condition:
		any of them
}

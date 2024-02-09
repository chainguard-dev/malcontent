rule mkdir {
	meta:
		description = "Uses libc functions to create directories"
		pledge = "wpath"
	strings:
		$mkdir = "mkdir" fullword
	condition:
		any of them
}

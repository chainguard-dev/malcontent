rule mkdir {
	meta:
		description = "Uses libc functions to create directories"
		pledge = "wpath"
	strings:
		$_mkdir = "_mkdir"
	condition:
		any of them
}

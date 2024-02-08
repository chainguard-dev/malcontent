rule mkdir {
	meta:
		description = "Uses libc functions to create directories"
		pledge = "wpath"
	strings:
		$mkdir = "mkdir" fullword
	condition:
		any of them
}

rule mkdtemp {
	meta:
		description = "Uses libc functions to create a temporary directory"
		pledge = "wpath"
	strings:
		$mkdtemp = "mkdtemp" fullword
	condition:
		any of them
}

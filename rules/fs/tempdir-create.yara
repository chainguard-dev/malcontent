
rule mkdtemp {
	meta:
		description = "Uses libc functions to create a temporary directory"
		pledge = "wpath"
	strings:
		$mkdtemp = "mkdtemp" fullword
		$tempdir = "temp dir"
	condition:
		any of them
}

rule libc {
	meta:
		pledge = "rpath"
	strings:
		$getcwd = "getcwd" fullword
	condition:
		any of them
}
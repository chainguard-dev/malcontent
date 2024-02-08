rule bsd_libc {
	meta:
		description = "Uses libc functions to list a directory"
		pledge = "rpath"
	strings:
		$opendir = "opendir" fullword
		$readdir = "readdir" fullword
	condition:
		any of them
}
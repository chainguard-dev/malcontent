rule rmdir {
	meta:
		description = "Uses libc functions to remove directories"
		pledge = "wpath"
	strings:
		$rmdir = "rmdir"
	condition:
		any of them
}

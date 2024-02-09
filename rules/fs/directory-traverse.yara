rule fts {
	meta:
		description = "Uses fts_* libc functions to traverse a file hierarchy"
		syscall = "openat,getdents"
		pledge = "rpath"
	strings:
		$fts_open = "_fts_open" fullword
		$fts_read = "_fts_read" fullword
		$fts_children = "_fts_children" fullword
		$fts_set = "_fts_set" fullword
		$fts_close = "_fts_close" fullword
	condition:
		2 of them
}
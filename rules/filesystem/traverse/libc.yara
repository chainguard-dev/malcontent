rule fts {
	meta:
		description = "Uses fts_* libc functions to traverse a file hierarchy"
		syscall_linux_fts_open = "openat,openat"
		syscall_linux_fts_children = "getdents"
		pledge = "rpath"
	strings:
		$fts_open = "fts_open"
		$fts_read = "fts_read"
		$fts_children = "fts_children"
		$fts_set = "fts_set"
		$fts_close = "fts_close"
	condition:
		2 of them
}
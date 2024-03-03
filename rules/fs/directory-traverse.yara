rule fts {
	meta:
		description = "traverse filesystem hierarchies"
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

rule py_walk : notable {
	meta:
		description = "traverse filesystem hierarchies"
	strings:
		$walk = "os.walk"
	condition:
		any of them
}
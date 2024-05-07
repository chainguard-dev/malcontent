rule rename : harmless {
	meta:
		syscall = "rename"
		pledge = "cpath"
	strings:
		$rename = "rename" fullword
		$renameat = "renameat" fullword
		$rename_file = "renameFile" fullword
	condition:
		any of them
}

rule rename : harmless {
	meta:
		syscall = "rename"
		pledge = "cpath"
	strings:
		$rename = "rename" fullword
		$renameat = "renameat" fullword
	condition:
		any of them
}

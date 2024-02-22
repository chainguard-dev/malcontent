rule readlink {
	meta:
		syscall = "readlink"
		description = "read value of a symbolic link"
		pledge = "rpath"
	strings:
		$ref = "readlink" fullword
		$ref2 = "readlinkat" fullword
	condition:
		any of them
}

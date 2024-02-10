rule mknod {
	meta:
		pledge = "wpath"
		syscall = "mknod"
		capability = "CAP_MKNOD"
		description = "able to make device files using mknod"
	strings:
		$ref = "mknod" fullword
	condition:
		any of them
}

rule mknodat {
	meta:
		pledge = "wpath"
		syscall = "mknodat"
		capability = "CAP_MKNOD"
		description = "able to make device files using mknod"
	strings:
		$ref2 = "mknodat" fullword
	condition:
		any of them
}

rule mknod {
	meta:
		pledge = "wpath"
		syscall = "mknod"
	strings:
		$chown = "mknod" fullword
	condition:
		any of them
}

rule mknodat {
	meta:
		pledge = "wpath"
		syscall = "mknodat"
	strings:
		$chown = "mknodat" fullword
	condition:
		any of them
}

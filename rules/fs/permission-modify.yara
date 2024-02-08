rule chmod {
	meta:
		description = "Uses libc functions to change file permissions"
		pledge = "wpath"
		syscall = "chmod"
	strings:
		$chmod = "chmod" fullword
		$_setmode = "_setmode" fullword
	condition:
		any of them
}


rule fchmod {
	meta:
		description = "Uses libc functions to change file permissions"
		pledge = "wpath"
		syscall = "fchmodat"
	strings:
		$fchmod = "fchmod" fullword
		$fchmodat = "fchmodat" fullword
	condition:
		any of them
}


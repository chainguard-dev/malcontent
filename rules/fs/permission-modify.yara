rule chmod {
	meta:
		description = "Change file permissions"
		pledge = "fattr"
		syscall = "chmod"
	strings:
		$chmod = "_chmod" fullword
		$dotChmod = ".Chmod" fullword
		$_setmode = "_setmode" fullword
	condition:
		any of them
}


rule fchmod {
	meta:
		description = "Uses libc functions to change file permissions"
		pledge = "fattr"
		syscall = "fchmodat"
	strings:
		$fchmod = "fchmod" fullword
		$dotfchmod = ".Fchmod" fullword
		$fchmodat = "fchmodat" fullword
	condition:
		any of them
}


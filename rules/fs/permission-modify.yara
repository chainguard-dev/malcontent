rule chmod {
	meta:
		description = "Modifies file permissions using chmod"
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
		description = "Modifies file permissions using fchmod"
		pledge = "fattr"
		syscall = "fchmodat"
	strings:
		$fchmod = "fchmod" fullword
		$dotfchmod = ".Fchmod" fullword
		$fchmodat = "fchmodat" fullword
	condition:
		any of them
}


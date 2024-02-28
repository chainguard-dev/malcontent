rule chmod : notable {
	meta:
		description = "Modifies file permissions using chmod"
		pledge = "fattr"
		syscall = "chmod"
	strings:
		$chmod = "chmod" fullword
		$dotChmod = "Chmod" fullword
		$_setmode = "_setmode" fullword
	condition:
		any of them
}


rule fchmod : notamble {
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


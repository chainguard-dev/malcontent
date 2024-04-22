rule chmod : notable {
	meta:
		description = "modifies file permissions"
		pledge = "fattr"
		syscall = "chmod"
		ref = "https://linux.die.net/man/1/chmod"
	strings:
		$chmod = "chmod" fullword
		$dotChmod = "Chmod" fullword
		$_setmode = "_setmode" fullword
	condition:
		any of them
}


rule fchmod : notamble {
	meta:
		description = "modifies file permissions"
		pledge = "fattr"
		syscall = "fchmodat"
		ref = "https://linux.die.net/man/2/fchmodat"
	strings:
		$fchmod = "fchmod" fullword
		$dotfchmod = ".Fchmod" fullword
		$fchmodat = "fchmodat" fullword
	condition:
		any of them
}
rule bsd_libc {
	meta:
		description = "Uses libc functions to change file permissions"
		pledge = "wpath"
	strings:
		$chmod = "chmod" fullword
		$fchmod = "fchmod" fullword
		$_setmode = "_setmode" fullword
	condition:
		any of them
}


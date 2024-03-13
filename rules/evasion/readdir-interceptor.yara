rule readdir_intercept : suspicious {
	meta:
		description = "userland rootkit designed to hide files"
	strings:
		$r_new65 = "readdir64" fullword
		$r_old64  = "_readdir64"
		$r_new32 = "readdir" fullword
		$r_old32  = "_readdir"

		$not_ld_debug = "LD_DEBUG"
		$not_libc = "getusershell"
	condition:
		uint32(0) == 1179403647 and all of ($r*) and none of ($not*)
}

rule readdir_intercept_source : suspicious {
	meta:
		description = "userland rootkit designed to hide files"
	strings:
		$declare = "DECLARE_READDIR"
		$hide = "hide"
	condition:
		all of them
}

rule lkm_dirent : suspicious {
	meta:
		description = "kernel rootkit designed to hide files"
	strings:
		$dirent = "linux_dirent"
		$Linux = "Linux"
	condition:
		all of them
}

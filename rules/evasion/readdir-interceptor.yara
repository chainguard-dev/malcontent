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
		all of ($r*) and none of ($not*)
}

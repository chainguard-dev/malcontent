
rule pty : notable {
	meta:
		description = "pseudo-terminal access functions"
		ref = "https://man7.org/linux/man-pages/man3/grantpt.3.html"
	strings:
		$grantpt = "grantpt" fullword
		$ptsname = "ptsname" fullword
		$posix_openpt = "posix_openpt" fullword
		$unlockpt = "unlockpt" fullword
	condition:
		2 of them
}

rule go_pty : notable {
	meta:
		description = "pseudo-terminal access from Go"
		ref = "https://github.com/creack/pty"
	strings:
		$ref = "creack/pty"
	condition:
		any of them
}

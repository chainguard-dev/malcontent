rule pty : notable {
	meta:
		description = "pseudo-terminal access functions"
	strings:
		$grantpt = "grantpt" fullword
		$ptsname = "ptsname" fullword
		$posix_openpt = "posix_openpt" fullword
		$unlockpt = "unlockpt" fullword
	condition:
		2 of them
}

rule go_pty : suspicious {
	meta:
		description = "pseudo-terminal access"
	strings:
		$ref = "creack/pty"
	condition:
		any of them
}

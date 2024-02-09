rule chown : harmless {
	meta:
		description = "Uses libc functions to change file permissions"
		pledge = "wpath"
		syscall = "chown"
		capability = "CAP_CHOWN"
	strings:
		$chown = "chown" fullword
	condition:
		any of them
}

rule fchown {
	meta:
		pledge = "wpath"
		syscall = "fchown"
		capability = "CAP_CHOWN"
	strings:
		$chown = "fchown" fullword
	condition:
		any of them
}

rule fchownat {
	meta:
		pledge = "wpath"
		syscall = "fchown"
		capability = "CAP_CHOWN"
	strings:
		$chown = "fchownat" fullword
	condition:
		any of them
}

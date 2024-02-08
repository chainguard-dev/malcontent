rule chown {
	meta:
		description = "Uses libc functions to change file permissions"
		pledge = "wpath"
		syscall = "chown"
	strings:
		$chown = "chown" fullword
	condition:
		any of them
}

rule fchown {
	meta:
		pledge = "wpath"
		syscall = "fchown"
	strings:
		$chown = "fchown" fullword
	condition:
		any of them
}

rule fchownat {
	meta:
		pledge = "wpath"
		syscall = "fchown"
	strings:
		$chown = "fchownat" fullword
	condition:
		any of them
}

rule chown : harmless {
	meta:
		description = "May change file ownership"
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
		description = "May change file ownership"
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
		description = "May change file ownership"
		pledge = "wpath"
		syscall = "fchown"
		capability = "CAP_CHOWN"
	strings:
		$chown = "fchownat" fullword
	condition:
		any of them
}

rule mkfifo {
	meta:
		pledge = "wpath"
		syscall = "chown"
	strings:
		$chown = "mkfifo" fullword
	condition:
		any of them
}

rule mkfifoat {
	meta:
		pledge = "wpath"
		syscall = "fchown"
	strings:
		$chown = "mkfifoat" fullword
	condition:
		any of them
}

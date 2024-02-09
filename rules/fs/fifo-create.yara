rule mkfifo {
	meta:
		pledge = "wpath"
		syscall = "mknodat"
	strings:
		$ref = "mkfifo" fullword
	condition:
		any of them
}

rule mkfifoat {
	meta:
		pledge = "wpath"
		syscall = "mknodat"
	strings:
		$ref = "mkfifoat" fullword
	condition:
		any of them
}


rule mlock {
	meta:
		pledge = "wpath"
		syscall = "mlock"
		description = "lcok memory"
		capability = "CAP_IPC_LOCK"
	strings:
		$ref = "mlock" fullword
		$ref2 = "mlock2" fullword
		$ref3 = "mlockall" fullword
	condition:
		any of them
}

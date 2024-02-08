rule fork {
	meta:
		pledge = "exec"
		syscall = "fork"
	strings:
		$fork = "_fork" fullword
	condition:
		any of them
}

rule syscall_vfork {
	meta:
		pledge = "exec"
		syscall = "vfork"
	strings:
		$vfork = "vfork" fullword
	condition:
		any of them
}


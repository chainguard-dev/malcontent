rule fork {
	meta:
		pledge = "exec"
		syscall = "fork"
		description = "Create a new child process using fork"
	strings:
		$fork = "_fork" fullword
	condition:
		any of them
}

rule syscall_vfork {
	meta:
		pledge = "exec"
		syscall = "vfork"
		description = "Create a new child process using vfork"
	strings:
		$vfork = "vfork" fullword
	condition:
		any of them
}


rule syscall_clone : harmless {
	meta:
		pledge = "exec"
		syscall = "clone"
		description = "Create a new child process using clone"
	strings:
		$clone = "clone" fullword
		$clone2 = "clone2" fullword
		$clone3 = "clone3" fullword
	condition:
		any of them
}


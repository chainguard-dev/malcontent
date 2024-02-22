
rule proc_listallpids {
	meta:
		pledge = "exec"
		syscall = "vfork"
	strings:
		$ref = "proc_listallpid" fullword
	condition:
		any of them
}


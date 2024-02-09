rule setuid {
	meta:
		syscall = "setuid"
		description = "set real and effective user ID of process"
		pledge = "id"
		capability = "CAP_SETUID"
	strings:
		$ref = "setuid" fullword
		$not_go = "_syscall.libc_setuid_trampoline"
		$not_ls = "file that is setuid"
	condition:
		$ref and none of ($not*)
}

rule seteuid {
	meta:
		syscall = "seteuid"
		description = "set effective user ID of process"
		pledge = "id"
		capability = "CAP_SETUID"
	strings:
		$ref = "seteuid" fullword
	condition:
		any of them
}

rule setreuid {
	meta:
		syscall = "setreuid"
		description = "set real and effective user ID of process"
		pledge = "id"
		capability = "CAP_SETUID"
	strings:
		$ref = "setreuid" fullword
	condition:
		any of them
}

rule setresuid {
	meta:
		syscall = "setresuid"
		description = "set real, effective, and saved user ID of process"
		pledge = "id"
		capability = "CAP_SETUID"
	strings:
		$ref = "setresuid" fullword
	condition:
		any of them
}

rule setfsuid {
	meta:
		syscall = "setfsuid"
		description = "set user identity used for filesystem checks"
		pledge = "id"
		capability = "CAP_SETUID"
	strings:
		$ref = "setfsuid" fullword
	condition:
		any of them
}

rule setuid {
	meta:
		syscall = "setuid"
		description = "set real and effective user ID of process"
		pledge = "id"
	strings:
		$ref = "setuid" fullword
	condition:
		any of them
}

rule seteuid {
	meta:
		syscall = "seteuid"
		description = "set effective user ID of process"
		pledge = "id"
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
	strings:
		$ref = "setresuid" fullword
	condition:
		any of them
}

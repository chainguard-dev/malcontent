rule ptrace : notable {
	meta:
		capability = "CAP_SYS_PTRACE"
		description = "trace or modify system calls"
	strings:
		$ref = "ptrace" fullword
	condition:
		any of them
}
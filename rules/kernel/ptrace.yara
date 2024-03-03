
rule ptrace : suspicious {
	meta:
		capability = "CAP_SYS_PTRACE"
		description = "Trace calls within arbitrary processes"
	strings:
		$ref = "ptrace" fullword
	condition:
		any of them
}
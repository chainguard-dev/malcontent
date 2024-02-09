
rule bpf {
	meta:
		capability = "CAP_SYS_BPF"
		description = "perform a command on an extended BPF map or program"
	strings:
		$ref = "bpf" fullword
	condition:
		any of them
}
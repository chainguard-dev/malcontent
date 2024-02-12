
rule bpf {
	meta:
		capability = "CAP_SYS_BPF"
		description = "BPF (Berkeley Packet Filter)"
	strings:
		$ref = "bpf" fullword
		$ref2 = "/dev/bpf"
	condition:
		any of them
}
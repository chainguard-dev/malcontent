
rule kallsyms : suspicious {
	meta:
		description = "access unexported kernel symbols"
		ref = "https://lwn.net/Articles/813350/"
	strings:
		$ref = "kallsyms_lookup_name" fullword

		$not_bpf = "BPF_FUNC_kallsyms_lookup_name"
	condition:
		$ref and none of ($not*)
}

rule kallsyms_lookup: high linux {
  meta:
    description                                                       = "access unexported kernel symbols"
    ref                                                               = "https://lwn.net/Articles/813350/"
    hash_2023_FontOnLake_1F52DB8E3FC3040C017928F5FFD99D9FA4757BF8_elf = "efbd281cebd62c70e6f5f1910051584da244e56e2a3228673e216f83bdddf0aa"
    hash_2023_FontOnLake_27E868C0505144F0708170DF701D7C1AE8E1FAEA_elf = "d7ad1bff4c0e6d094af27b4d892b3398b48eab96b64a8f8a2392e26658c63f30"
    hash_2023_FontOnLake_45E94ABEDAD8C0044A43FF6D72A5C44C6ABD9378_elf = "f60c1214b5091e6e4e5e7db0c16bf18a062d096c6d69fe1eb3cbd4c50c3a3ed6"
    filetypes                                                         = "so,elf"

  strings:
    $ref           = "kallsyms_lookup_name" fullword
    $not_bpf       = "BPF_FUNC_kallsyms_lookup_name"
    $not_linux_src = "GPL-2.0 WITH Linux"
    $not_include   = "#define "

  condition:
    filesize < 1MB and $ref and none of ($not*)
}

rule kallsyms: medium linux {
  meta:
    description = "access kernel symbols"

  strings:
    $kallsyms = "/proc/kallsyms"

  condition:
    any of them
}

rule bpftrace: override linux {
  meta:
    description = "bpftrace"
    filetypes   = "so,elf"
    kallsyms    = "medium"

  strings:
    $ref2 = "BPFTRACE" fullword

  condition:
    filesize < 2MB and any of them
}

rule bpf: override linux {
  meta:
    description     = "libbpf"
    filetypes       = "so,elf"
    kallsyms_lookup = "medium"

  strings:
	$ref = "BPF" fullword
    $ref2 = "LIBBPF" fullword

  condition:
    filesize < 2MB and any of them
}

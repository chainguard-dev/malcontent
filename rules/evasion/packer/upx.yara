
rule upx : high {
  meta:
    description = "Binary is packed with UPX"
    hash_2023_UPX_0c25 = "0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d"
    hash_2023_UPX_5a59 = "5a5960ccd31bba5d47d46599e4f10e455b74f45dad6bc291ae448cef8d1b0a59"
    hash_2023_FontOnLake_38B09D690FAFE81E964CBD45EC7CF20DCB296B4D_elf = "f155fafa36d1094433045633741df98bbbc1153997b3577c3fa337cc525713c0"
  strings:
    $u_upx_sig = "UPX!"
    $u_packed = "executable packer"
    $u_is_packed = "This file is packed"
    $not_upx = "UPX_DEBUG_DOCTEST_DISABLE"
  condition:
    any of ($u*) in (0..1024) and none of ($not*)
}

rule upx_elf : high {
  meta:
    description = "Linux ELF binary packed with UPX"
    hash_2023_UPX_0c25 = "0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d"
    hash_2023_UPX_5a59 = "5a5960ccd31bba5d47d46599e4f10e455b74f45dad6bc291ae448cef8d1b0a59"
    hash_2023_FontOnLake_1F52DB8E3FC3040C017928F5FFD99D9FA4757BF8_elf = "efbd281cebd62c70e6f5f1910051584da244e56e2a3228673e216f83bdddf0aa"
  strings:
    $proc_self = "/proc/self/exe"
    $prot_exec = "PROT_EXEC|PROT_WRITE failed"
  condition:
    uint32(0) == 1179403647 and $prot_exec and $proc_self
}

rule upx_elf_tampered : critical {
  meta:
    description = "Linux ELF binary packed with modified UPX"
    hash_2023_Unix_Trojan_DarkNexus_2527 = "2527fc4d6491bd8fc9a79344790466eaedcce8795efe540ac323ea93e59c5ab5"
    hash_2023_Unix_Trojan_DarkNexus_2e1d = "2e1d9acd6ab43d63f3eab9fc995080fc67a0a5bbdc66be3aff53ed3745c9e811"
    hash_2023_Unix_Trojan_DarkNexus_3a55 = "3a55dcda90c72acecb548f4318d41708bb73c4c3fb099ff65c988948dc8b216f"
  strings:
    $prot_exec = "PROT_EXEC|PROT_WRITE failed"
    $upx = "UPX!"
  condition:
    uint32(0) == 1179403647 and $prot_exec and not $upx
}

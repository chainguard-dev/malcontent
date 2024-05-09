
rule boot_path : medium {
  meta:
    description = "path reference within /boot"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_kill_loop = "a34a36ec6b7b209aaa2092cc28bc65917e310b3181e98ab54d440565871168cb"
  strings:
    $ref = /\/boot\/[\%\w\.\-\/]{4,32}/ fullword
  condition:
    $ref
}

rule elf_boot_path : medium {
  meta:
    description = "path reference within /boot"
    hash_2023_Unix_Malware_Kaiji_3e68 = "3e68118ad46b9eb64063b259fca5f6682c5c2cb18fd9a4e7d97969226b2e6fb4"
    hash_2023_Unix_Malware_Kaiji_f4a6 = "f4a64ab3ffc0b4a94fd07a55565f24915b7a1aaec58454df5e47d8f8a2eec22a"
    hash_2023_Unix_Trojan_IptabLex_b574 = "b5745c865ab5348425e79ce91d79442982c20f3f89e1ffcdd2816895a25d2a1c"
  strings:
    $ref = /\/boot\/[\%\w\.\-\/]{4,32}/ fullword
    $not_kern = "/boot/vmlinux-%s"
    $not_include_path = "_PATH_UNIX" fullword
  condition:
    uint32(0) == 1179403647 and $ref and none of ($not*)
}

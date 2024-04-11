import "math"

rule obfuscated_elf : suspicious {
  meta:
    hash_Gafgyt = "09b8159120088fea909b76f00280e3ebca23a54f2b41d967d0c89ebb82debdbf"
    hash_2023_icmpshell = "4305c04df40d3ac7966289cc0a81cedbdd4eee2f92324b26fe26f57f57265bca"
    hash_2023_Downloads_5f73 = "5f73f54865a1be276d39f5426f497c21e44a309e165e5e2d02f5201e8c1f05e0"
    hash_2023_trojan_Mirai_ubzhp = "98e7808bd5bfd72c08429ffe0ffb52ae54bce7e6389f17ae523e8ae0099489ab"
    hash_2023_trojan_Mirai_thiwm = "abf0f87cc7eb6028add2e2bda31ede09709a948e8f7e56390a3f18d1eae58aa6"
    hash_2023_Downloads_b6f5 = "b6f51ce14ba12fd254da8fa40e7fef20b76e9df57660b66121e5f16718797320"
    hash_2023_trojan_Mirai_ghwow = "c91c6dbfa746e3c49a6c93f92b4d6c925668e620d4effc5b2bf59cf9100fe87d"
    hash_2023_Downloads_f5de = "f5de75a6db591fe6bb6b656aa1dcfc8f7fe0686869c34192bfa4ec092554a4ac"
	description = "Obfuscated ELF binary (missing content)"
  strings:
    $dlsym = "dlsym" fullword
    $gcc = "gcc" fullword
    $libstdc = "libstdc" fullword
    $glibc = "glibc" fullword 
	$setsid = "setsid" fullword
	$gmon = "__gmon_start__"
	$glibc2 = "@GLIBC"
	$cxa = "__cxa_finalize"
	$dereg = "__deregister_frame_info"
	$symtab = ".symtab" fullword
	$__libc_start_main = "__libc_start_main"
  condition:
    uint32(0) == 1179403647 and none of them
}


rule high_entropy_elf : suspicious {
  meta:
	description = "Obfuscated ELF binary (high entropy content)"
  strings:
	$not_pyinst = "pyi-bootloader-ignore-signals"
	$not_go = "syscall_linux.go"
	$not_go2 = "vdso_linux.go"
  condition:
    uint32(0) == 1179403647 and math.entropy(1200,4096) > 7 and none of ($not*)
}

import "math"

rule obfuscated_elf : high linux {
  meta:
    description = "Obfuscated ELF binary (missing symbols)"
    hash_2023_APT31_1d60 = "1d60edb577641ce47dc2a8299f8b7f878e37120b192655aaf80d1cde5ee482d2"
    hash_2023_UPX_0c25 = "0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d"
    hash_2023_Earthwrom_1ae6 = "1ae62dbec330695d2eddc7cb9a65d47bad5f45af95e6c8a803f0780e0749a3ad"
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
	$go_export = ".go_export"
	$Usage = "Usage:" fullword
	$usage = "usage:" fullword
	$build_id = ".note.gnu.build-id" fullword
	$invalid = "invalid" fullword
	$debuglink = ".gnu_debuglink" fullword
  condition:
    uint32(0) == 1179403647 and none of them
}

rule high_entropy_header : high {
  meta:
    description = "high entropy ELF header (>7)"
    hash_2023_UPX_0c25 = "0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d"
    hash_2023_UPX_5a59 = "5a5960ccd31bba5d47d46599e4f10e455b74f45dad6bc291ae448cef8d1b0a59"
    hash_2023_FontOnLake_38B09D690FAFE81E964CBD45EC7CF20DCB296B4D_elf = "f155fafa36d1094433045633741df98bbbc1153997b3577c3fa337cc525713c0"
  strings:
    $not_pyinst = "pyi-bootloader-ignore-signals"
    $not_go = "syscall_linux.go"
    $not_go2 = "vdso_linux.go"
  condition:
    uint32(0) == 1179403647 and math.entropy(1200, 4096) > 7 and none of ($not*)
}

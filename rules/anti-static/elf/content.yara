import "elf"

rule obfuscated_elf: high linux {
  meta:
    description          = "Obfuscated ELF binary (missing symbols)"
    hash_2023_APT31_1d60 = "1d60edb577641ce47dc2a8299f8b7f878e37120b192655aaf80d1cde5ee482d2"
    hash_2023_UPX_0c25   = "0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d"

  strings:
    $dlsym             = "dlsym" fullword
    $gcc               = "gcc" fullword
    $libstdc           = "libstdc" fullword
    $glibc             = "glibc" fullword
    $setsid            = "setsid" fullword
    $gmon              = "__gmon_start__"
    $glibc2            = "@GLIBC"
    $cxa               = "__cxa_finalize"
    $dereg             = "__deregister_frame_info"
    $symtab            = ".symtab" fullword
    $__libc_start_main = "__libc_start_main"
    $go_export         = ".go_export"
    $Usage             = "Usage:" fullword
    $usage             = "usage:" fullword
    $build_id          = ".note.gnu.build-id" fullword
    $invalid           = "invalid" fullword
    $debuglink         = ".gnu_debuglink" fullword

  condition:
    filesize > 512 and elf.type == elf.ET_EXEC and uint32(0) == 1179403647 and none of them
}

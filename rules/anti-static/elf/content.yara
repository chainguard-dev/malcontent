import "elf"

rule obfuscated_elf: high linux {
  meta:
    description = "Obfuscated ELF binary (missing symbols)"
    filetypes   = "elf"

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

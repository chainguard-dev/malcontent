rule tls_get_addr: medium {
  meta:
    description = "looks up thread private variables, may be used for loaded library discovery"
    ref         = "https://chao-tic.github.io/blog/2018/12/25/tls"

  strings:
    $val = "__tls_get_addr" fullword

  condition:
    any of them
}

import "elf"
import "math"

rule sus_dylib_tls_get_addr: high {
  meta:
    description = "suspicious runtime dependency resolution"

  strings:
    $val               = "__tls_get_addr" fullword
    $not_trampoline    = "__interceptor_trampoline"
    $not_glibc_private = "GLIBC_PRIVATE"

  condition:
    filesize < 500KB and elf.type == elf.ET_DYN and $val and none of ($not*) and math.entropy(1, filesize) >= 6
}

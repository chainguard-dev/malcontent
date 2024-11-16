private rule small_macho {
  condition:
    filesize < 1MB and (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962)
}

import "math"

rule macho_opaque_binary: high {
  meta:
    description = "opaque binary executes mystery command-lines"

  strings:
    $word_with_spaces = /[a-z]{2,16} [a-uxyz]{2,16}/ fullword
    $libc_call        = /@_[a-z]{3,12}/ fullword
    $f_system         = "@_system" fullword
    $not_gmon_start   = "__gmon_start__"
    $not_usage        = "usage:" fullword
    $not_usage2       = "Usage:" fullword
    $not_USAGE        = "USAGE:" fullword
    $not_java         = "java/lang"

  condition:
    small_macho and #word_with_spaces < 8 and #libc_call < 6 and all of ($f*) and none of ($not*)
}

rule macho_opaque_binary_long_str: high {
  meta:
    description = "opaque binary executes mystery command-lines, contains large alphanumeric string"

  strings:
    $word_with_spaces = /[a-z]{2,16} [a-uxyz]{2,16}/ fullword
    $libc_call        = /@_[a-z]{3,12}/ fullword
    $f_system         = "@_system" fullword
    $not_gmon_start   = "__gmon_start__"
    $not_usage        = "usage:" fullword
    $not_usage2       = "Usage:" fullword
    $not_USAGE        = "USAGE:" fullword
    $not_java         = "java/lang"

    $long_low_str = /\x00[a-z0-9]{3000}/

  condition:
    small_macho and #word_with_spaces < 10 and #libc_call < 15 and all of ($f*) and any of ($long*) and none of ($not*)
}

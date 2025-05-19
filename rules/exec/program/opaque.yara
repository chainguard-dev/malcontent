private rule program_small_macho {
  strings:
    $stub_helper = "__stub_helper"

  condition:
    filesize < 1MB and (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and $stub_helper
}

import "math"

rule macho_opaque_binary: high {
  meta:
    description = "opaque binary executes mystery command-lines"
    filetypes   = "macho"

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
    program_small_macho and #word_with_spaces < 8 and #libc_call < 6 and all of ($f*) and none of ($not*)
}

rule macho_opaque_binary_long_str: high {
  meta:
    description = "opaque binary executes mystery command-lines, contains large alphanumeric string"
    filetypes   = "macho"

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
    program_small_macho and #word_with_spaces < 10 and #libc_call < 15 and all of ($f*) and any of ($long*) and none of ($not*)
}

rule decoded_or_encoded_cmd: medium {
  meta:
    description = "references an encoded command"

  strings:
    $r_encoded_cmd = "encoded_cmd" fullword
    $r_decoded_cmd = "decoded_cmd" fullword

  condition:
    any of ($r*)
}

rule exec_decoded_or_encoded_cmd: high {
  meta:
    description = "executes an encoded command"

  strings:
    $r_encoded_cmd = "encoded_cmd" fullword
    $r_decoded_cmd = "decoded_cmd" fullword
    $e_system      = "system" fullword
    $exec          = "exec" fullword
    $execl         = "execl" fullword
    $execle        = "execle" fullword
    $execlp        = "execlp" fullword
    $execv         = "execv" fullword
    $execvp        = "execvp" fullword
    $execvP        = "execvP" fullword

  condition:
    any of ($r*) and any of ($e*)
}

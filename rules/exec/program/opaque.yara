import "math"

include "rules/global/global.yara"

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
    global_small_macho and #word_with_spaces < 8 and #libc_call < 6 and all of ($f*) and none of ($not*)
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
    global_stub_macho and #word_with_spaces < 10 and #libc_call < 15 and all of ($f*) and any of ($long*) and none of ($not*)
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

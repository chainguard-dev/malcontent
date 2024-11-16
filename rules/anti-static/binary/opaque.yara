import "math"

rule opaque_binary: medium {
  meta:
    description = "binary contains little text content"

  strings:
    $word_with_spaces = /[a-z]{2,16} [a-uxyz]{2,16}/ fullword
    $not_gmon_start   = "__gmon_start__"
    $not_usage        = "usage:" fullword
    $not_usage2       = "Usage:" fullword
    $not_USAGE        = "USAGE:" fullword
    $not_java         = "java/lang"

  condition:
    filesize < 52428800 and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and #word_with_spaces < 4 and none of ($not*)
}

rule mystery_regex_binary: high {
  meta:
    description = "opaque binary with suspicious libc calls and regex usage"

  strings:
    $f_environ = "environ" fullword
    $f_chdir   = "chdir" fullword
    $f_fork    = "fork" fullword
    $f_fopen   = "fopen" fullword
    $f_fwrite  = "fwrite" fullword
    $f_mkdir   = "mkdir" fullword
    $f_opendir = "opendir" fullword
    $f_rand    = "rand" fullword
    $f_popen   = "popen" fullword
    $f_readdir = "readdir" fullword
    $f_srand   = "srand" fullword
    $f_regexec = "regexec" fullword
    $f_umask   = "umask" fullword

  condition:
    filesize < 512KB and opaque_binary and math.entropy(1, filesize) >= 3.6 and all of them
}
